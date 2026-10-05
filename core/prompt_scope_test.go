package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type contextPromptTools struct {
	testTools
	load func(PromptContext) (PromptResult, error)
}

func (p contextPromptTools) PromptContext(_ context.Context, req PromptContext) (PromptResult, error) {
	return p.load(req)
}

type legacyPromptTools struct{ testTools }

func (legacyPromptTools) Prompt(context.Context, string) (string, error) {
	return WrapDataSection("memory", "legacy-extra"), nil
}

func TestContextPromptFanout(t *testing.T) {
	files := []string{"src/a.go"}
	first := contextPromptTools{load: func(r PromptContext) (PromptResult, error) {
		r.ActiveFiles[0] = "mutated"
		return PromptResult{Text: WrapDataSection("project_docs", "owned"), ProjectDocs: true}, nil
	}}
	second := contextPromptTools{load: func(r PromptContext) (PromptResult, error) {
		if r.ActiveFiles[0] != "src/a.go" {
			t.Fatal("provider mutated another provider's scope")
		}
		return PromptResult{Text: WrapDataSection("rules", "second")}, nil
	}}
	sets, err := CombineToolsets(first, legacyPromptTools{}, second)
	if err != nil {
		t.Fatal(err)
	}
	r, err := sets.PromptContext(context.Background(), PromptContext{WorkDir: t.TempDir(), ActiveFiles: files})
	if err != nil || !r.ProjectDocs || !strings.Contains(r.Text, "legacy-extra") || !strings.Contains(r.Text, "second") || files[0] != "src/a.go" {
		t.Fatal(r, err, files)
	}
	duplicate, _ := CombineToolsets(first, first)
	if _, err := duplicate.PromptContext(context.Background(), PromptContext{ActiveFiles: files}); err == nil {
		t.Fatal("duplicate owners accepted")
	}
}

func TestEngineContextPromptOwnership(t *testing.T) {
	for _, kind := range []string{"owned", "empty-owned", "legacy", "error", "plain"} {
		t.Run(kind, func(t *testing.T) {
			wd, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(wd, "AGENTS.md"), []byte("fallback-marker"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(wd, "CLAUDE.md"), []byte("ignored-legacy-doc"), 0600); err != nil {
				t.Fatal(err)
			}
			var set Toolset
			switch kind {
			case "owned", "empty-owned", "error":
				set = contextPromptTools{load: func(r PromptContext) (PromptResult, error) {
					if !reflect.DeepEqual(r.ActiveFiles, []string{"src/a.go"}) {
						t.Errorf("scope: %v", r.ActiveFiles)
					}
					if kind == "error" {
						return PromptResult{}, errors.New("private context failure")
					}
					text := ""
					if kind == "owned" {
						text = WrapDataSection("project_docs", "owned-marker")
					}
					return PromptResult{Text: text, ProjectDocs: true}, nil
				}}
			case "legacy":
				set = legacyPromptTools{}
			}
			sets, err := CombineToolsets(set)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			m := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
				called = true
				p := r.Messages[0].Content
				wantFallback := kind == "legacy" || kind == "plain"
				if strings.Contains(p, "fallback-marker") != wantFallback || strings.Contains(p, "ignored-legacy-doc") {
					t.Errorf("fallback: %s", p)
				}
				if kind == "owned" && strings.Count(p, "owned-marker") != 1 {
					t.Errorf("ownership: %s", p)
				}
				if kind == "legacy" && !strings.Contains(p, "legacy-extra") {
					t.Errorf("legacy source: %s", p)
				}
				return ModelResponse{Content: "done"}, nil
			})
			e, err := New(Options{WorkDir: wd, Model: m, Tools: sets})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			files := []string{filepath.Join(wd, "src/a.go")}
			ch, err := e.SendMessage(ChatRequest{Message: "scope", ActiveFiles: files})
			if err != nil {
				t.Fatal(err)
			}
			files[0] = "changed-after-send"
			events := collect(t, ch)
			if kind == "error" {
				if called || !strings.Contains(eventText(events), "context_error") || strings.Contains(eventText(events), "private context failure") {
					t.Fatal(events)
				}
			} else if !called {
				t.Fatal(events)
			}
		})
	}
}

func TestNormalizeActiveFiles(t *testing.T) {
	wd := t.TempDir()
	files, err := NormalizeActiveFiles(wd, []string{"src/a.go", filepath.Join(wd, "src/a.go"), "src/../b.go"})
	if err != nil || !reflect.DeepEqual(files, []string{"src/a.go", "b.go"}) {
		t.Fatal(files, err)
	}
	for _, bad := range [][]string{{"../outside"}, {filepath.Join(t.TempDir(), "x")}, {""}, {"."}, {"C:\\outside"}, {"x\x00y"}, {strings.Repeat("x", 4097)}, make([]string, 129)} {
		if _, err := NormalizeActiveFiles(wd, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		t.Error("invalid scope reached model")
		return ModelResponse{}, nil
	}), nil)
	if _, err := e.SendMessage(ChatRequest{Message: "bad", ActiveFiles: []string{"../outside"}}); err == nil {
		t.Fatal("engine accepted escape")
	}
}
