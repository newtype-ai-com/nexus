package core

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/newtype-ai-com/nexus/ids"
)

// sortedSpecs advertises every tool: both turn modes (auto, self-conscious)
// have the same tool surface. Policy stays with Binding.Gate and approvals.
func sortedSpecs(tools map[string]Tool) []ToolSpec {
	specs := make([]ToolSpec, 0, len(tools))
	for _, tool := range tools {
		specs = append(specs, tool.Spec)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	return specs
}
func textToolsPrompt(specs []ToolSpec) string {
	raw, _ := json.Marshal(specs)
	return "Call tools with <tool_call>{\"name\":\"tool_name\",\"arguments\":{...}}</tool_call>. Do not simulate tool results. Available tools:\n" + string(raw)
}
func parseTextToolCalls(text string) (string, []ToolCall) {
	var calls []ToolCall
	var visible strings.Builder
	for {
		start := strings.Index(text, "<tool_call>")
		if start < 0 {
			visible.WriteString(text)
			break
		}
		visible.WriteString(text[:start])
		text = text[start+len("<tool_call>"):]
		end := strings.Index(text, "</tool_call>")
		raw := text
		if end < 0 {
			text = ""
		} else {
			raw = text[:end]
			text = text[end+len("</tool_call>"):]
		}
		raw = strings.TrimSpace(raw)
		if strings.HasPrefix(raw, "```") {
			if i := strings.IndexByte(raw, '\n'); i >= 0 {
				raw = raw[i+1:]
			} else {
				raw = ""
			}
			raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "```"))
		}
		var call ToolCall
		if json.Unmarshal([]byte(raw), &call) != nil || call.Name == "" || end < 0 {
			call = ToolCall{Name: "invalid_tool_call", Arguments: json.RawMessage(`{}`)}
		}
		call.ID = ids.New(ids.KindAction)
		calls = append(calls, call)
	}
	return strings.TrimSpace(visible.String()), calls
}
func stripThink(text string) string {
	for {
		start := strings.Index(text, "<think>")
		if start < 0 {
			return strings.TrimSpace(text)
		}
		end := strings.Index(text[start+7:], "</think>")
		if end < 0 {
			return strings.TrimSpace(text[:start])
		}
		text = text[:start] + text[start+7+end+8:]
	}
}
