// Package streamprogress shares model-stream liveness semantics between the
// gateway and clients. Transport bytes alone are never evidence of progress.
package streamprogress

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

const maxFrame = 256 << 10

// Tokenize only the root keys. Nested content is never an event type and
// duplicate type keys (including escaped keys) are ambiguous, not progress.
func topLevelType(data []byte) (string, bool) {
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return "", false
	}
	typ := ""
	seen := false
	for d.More() {
		k, err := d.Token()
		if err != nil {
			return "", false
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return "", false
		}
		if k == "type" {
			if seen || len(raw) == 0 || raw[0] != '"' {
				return "", false
			}
			seen = true
			if json.Unmarshal(raw, &typ) != nil {
				return "", false
			}
		}
	}
	if _, err = d.Token(); err != nil {
		return "", false
	}
	if _, err = d.Token(); err != io.EOF {
		return "", false
	}
	return typ, true
}

// StreamProgress accepts arbitrary transport chunks. Only a complete SSE frame
// can advance progress. Oversized or malformed frames fail closed; storage is
// bounded independently of line length. Last never contains provider text.
// A StreamProgress is owned by one reader (Watch serializes concurrent access).
type StreamProgress struct {
	line, data                       []byte
	header                           string
	oversized, lineOverflow, hasData bool
	cr                               bool
	Last                             string
}

func KeepAliveEvent(typ string) bool {
	t := strings.ToLower(typ)
	if t == "ping" || strings.HasSuffix(t, ".ping") {
		return true
	}
	for _, s := range []string{"keepalive", "keep-alive", "keep_alive", "heartbeat"} {
		if strings.Contains(t, s) {
			return true
		}
	}
	return false
}

// safeType is an allowlist, not a character filter: even a valid identifier
// supplied by an upstream can be a credential or reflected user text.
func safeType(t string) string {
	switch t {
	case "data", "comment", "done", "ping", "keepalive", "keep-alive", "keep_alive", "heartbeat",
		"response.created", "response.in_progress", "response.completed", "response.failed", "response.incomplete",
		"response.output_text.delta", "response.output_text.done", "response.output_item.added", "response.output_item.done",
		"response.content_part.added", "response.content_part.done", "response.function_call_arguments.delta", "response.function_call_arguments.done",
		"response.reasoning_summary_text.delta", "response.refusal.delta", "error",
		"message_start", "message_delta", "message_stop", "content_block_start", "content_block_delta", "content_block_stop":
		return t
	}
	return "unknown"
}

func (s *StreamProgress) Feed(p []byte) bool {
	progress := false
	for _, b := range p {
		if s.cr {
			s.cr = false
			if b == '\n' {
				continue
			}
		}
		if b == '\r' || b == '\n' {
			if s.endLine() {
				progress = true
			}
			s.line = s.line[:0]
			s.lineOverflow = false
			s.cr = b == '\r'
		} else if len(s.line) < maxFrame {
			s.line = append(s.line, b)
		} else {
			s.lineOverflow = true
			s.oversized = true
		}
	}
	return progress
}

func (s *StreamProgress) endLine() bool {
	l := s.line
	if len(l) == 0 && !s.lineOverflow {
		defer func() { s.data = s.data[:0]; s.header = ""; s.oversized = false; s.hasData = false }()
		if !s.hasData {
			return false
		}
		if s.oversized {
			s.Last = "unknown"
			return false
		}
		data := bytes.TrimSpace(s.data)
		typ := s.header
		if KeepAliveEvent(typ) {
			s.Last = safeType(typ)
			return false
		}
		if len(data) == 0 {
			s.Last = "unknown"
			return false
		}
		if bytes.Equal(data, []byte("[DONE]")) {
			s.Last = "done"
			return true
		}
		if len(data) > 0 {
			typValue, ok := topLevelType(data)
			if !ok {
				s.Last = "unknown"
				return false
			}
			if typValue != "" {
				typ = typValue
			}
		}
		if typ == "" {
			typ = "data"
		}
		s.Last = safeType(typ)
		return !KeepAliveEvent(typ)
	}
	if len(l) > 0 && l[0] == ':' {
		s.Last = "comment"
		return false
	}
	key, val, _ := bytes.Cut(l, []byte(":"))
	val = bytes.TrimPrefix(val, []byte(" "))
	switch string(key) {
	case "event":
		if len(val) > 256 || s.lineOverflow {
			s.oversized = true
			s.header = ""
		} else {
			s.header = string(val)
		}
	case "data":
		s.hasData = true
		if len(s.data)+len(val)+1 > maxFrame || s.lineOverflow {
			s.oversized = true
		} else if !s.oversized {
			s.data = append(s.data, val...)
			s.data = append(s.data, '\n')
		}
	}
	return false
}
