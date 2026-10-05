package core

import (
	"context"
	"errors"
)

// PromptSource is an explicitly configured context provider. Returned sections
// MUST already be neutralized with WrapDataSection; implementations are trusted
// code but their filesystem/network content is untrusted data.
type PromptSource interface {
	Prompt(context.Context, string) (string, error)
}

// PromptContext carries advisory file scope, never filesystem authority. Paths
// are workspace-relative or absolute inside WorkDir; nil/empty means unknown.
type PromptContext struct {
	WorkDir     string
	ActiveFiles []string
}

type PromptResult struct {
	Text string
	// ProjectDocs suppresses the engine's fallback root-document loader even
	// when filtering produced no text. At most one provider may own this layer.
	ProjectDocs bool
}

type ContextPromptSource interface {
	PromptContext(context.Context, PromptContext) (PromptResult, error)
}

func loadPrompt(ctx context.Context, set Toolset, request PromptContext) (PromptResult, error) {
	request.ActiveFiles = append([]string(nil), request.ActiveFiles...)
	if p, ok := set.(ContextPromptSource); ok {
		return p.PromptContext(ctx, request)
	}
	if p, ok := set.(PromptSource); ok {
		text, err := p.Prompt(ctx, request.WorkDir)
		return PromptResult{Text: text}, err
	}
	return PromptResult{}, nil
}

// ToolResultSource supplies optional, already-neutralized context after a
// successful built-in tool call. It must not change execution status or perform
// writes. It is not consulted for denied, failed, or external tools.
type ToolResultSource interface {
	ToolResultContext(context.Context, ToolContext, ToolCall) string
}

// ToolSpecFilter narrows built-in schemas advertised to a model. It is not an
// authorization boundary: the execution registry and policy Gate remain intact.
// Bound tools are not owned by this Toolset and are not filtered here.
type ToolSpecFilter interface {
	AdvertiseTool(name string) bool
}

type TurnCloser interface {
	EndTurn(sessionID, turnID string)
}

// Toolsets combines independently owned tool capabilities without silent name
// shadowing. Closing and per-session/turn cleanup fan out to every provider.
type Toolsets struct{ sets []Toolset }

func CombineToolsets(sets ...Toolset) (*Toolsets, error) {
	seen := map[string]bool{}
	for _, set := range sets {
		if set == nil {
			continue
		}
		for _, tool := range set.Tools() {
			if tool.Spec.Name == "" || seen[tool.Spec.Name] {
				return nil, errors.New("empty or duplicate tool name")
			}
			seen[tool.Spec.Name] = true
		}
	}
	return &Toolsets{sets: append([]Toolset(nil), sets...)}, nil
}
func (s *Toolsets) Tools() []Tool {
	var out []Tool
	for _, set := range s.sets {
		if set != nil {
			out = append(out, set.Tools()...)
		}
	}
	return out
}
func (s *Toolsets) Close() error {
	var errs []error
	for _, set := range s.sets {
		if set != nil {
			errs = append(errs, set.Close())
		}
	}
	return errors.Join(errs...)
}

// SuspendExecution preserves local session state. Providers with external
// lifetimes must explicitly implement this hook; Close may delete local state.
func (s *Toolsets) SuspendExecution() error {
	var errs []error
	for _, set := range s.sets {
		if c, ok := set.(interface{ SuspendExecution() error }); ok {
			errs = append(errs, c.SuspendExecution())
		}
	}
	return errors.Join(errs...)
}

func (s *Toolsets) CloseSession(id string) error {
	var errs []error
	for _, set := range s.sets {
		if c, ok := set.(interface{ CloseSession(string) error }); ok {
			errs = append(errs, c.CloseSession(id))
		}
	}
	return errors.Join(errs...)
}
func (s *Toolsets) EndTurn(id, turn string) {
	for _, set := range s.sets {
		if c, ok := set.(TurnCloser); ok {
			c.EndTurn(id, turn)
		}
	}
}

// Context providers are advisory: a panic must not turn a completed write into
// a reported failure that the model might repeat.
func toolResultContext(ctx context.Context, set Toolset, tc ToolContext, call ToolCall) (text string) {
	defer func() {
		if recover() != nil {
			text = ""
		}
	}()
	if p, ok := set.(ToolResultSource); ok {
		return p.ToolResultContext(ctx, tc, call)
	}
	return ""
}

func (s *Toolsets) ToolResultContext(ctx context.Context, tc ToolContext, call ToolCall) string {
	var text string
	for _, set := range s.sets {
		if p, ok := set.(ToolResultSource); ok {
			text += p.ToolResultContext(ctx, tc, call)
		}
	}
	return text
}

func (s *Toolsets) Prompt(ctx context.Context, wd string) (string, error) {
	result, err := s.PromptContext(ctx, PromptContext{WorkDir: wd})
	return result.Text, err
}

func (s *Toolsets) PromptContext(ctx context.Context, request PromptContext) (PromptResult, error) {
	var result PromptResult
	for _, set := range s.sets {
		part, err := loadPrompt(ctx, set, request)
		if err != nil {
			return PromptResult{}, err
		}
		if part.ProjectDocs && result.ProjectDocs {
			return PromptResult{}, errors.New("multiple project document providers")
		}
		result.ProjectDocs = result.ProjectDocs || part.ProjectDocs
		if part.Text != "" {
			result.Text += "\n" + part.Text
		}
	}
	return result, nil
}
