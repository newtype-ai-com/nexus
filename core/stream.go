package core

import "strings"

// visibleStream strips reasoning across arbitrary token boundaries and redacts
// complete lines before publishing them. The last line is held until completion:
// token-wise redaction could otherwise leak a secret split across callbacks.
// PEM blocks are held in their entirety. This is defense in depth, not detection
// of arbitrary unknown secrets. content_done remains the canonical full answer.
type visibleStream struct {
	pending string
	line    string
	hidden  bool
	emit    func(string)
}

func (s *visibleStream) write(text string) {
	s.pending += text
	for s.pending != "" {
		tag := "<think>"
		if s.hidden {
			tag = "</think>"
		}
		if i := strings.Index(s.pending, tag); i >= 0 {
			if !s.hidden {
				s.visible(s.pending[:i])
			}
			s.pending = s.pending[i+len(tag):]
			s.hidden = !s.hidden
			continue
		}
		keep := 0
		for n := 1; n < len(tag) && n <= len(s.pending); n++ {
			if strings.HasSuffix(s.pending, tag[:n]) {
				keep = n
			}
		}
		if !s.hidden {
			s.visible(s.pending[:len(s.pending)-keep])
		}
		s.pending = s.pending[len(s.pending)-keep:]
		return
	}
}
func (s *visibleStream) visible(text string) {
	s.line += text
	for {
		i := strings.IndexByte(s.line, '\n')
		if i < 0 {
			return
		}
		if strings.Contains(s.line[:i], "-----BEGIN") {
			end := strings.Index(s.line, "-----END")
			if end < 0 {
				return
			}
			tail := strings.IndexByte(s.line[end:], '\n')
			if tail < 0 {
				return
			}
			i = end + tail
		}
		s.emit(clean(s.line[:i+1]))
		s.line = s.line[i+1:]
	}
}
func (s *visibleStream) finish() {
	if !s.hidden {
		s.line += s.pending
	}
	// Never publish an unterminated private-key block.
	if i := strings.Index(s.line, "-----BEGIN"); i >= 0 && !strings.Contains(s.line[i:], "-----END") {
		s.line = s.line[:i] + "[withheld: incomplete key block]"
	}
	if s.line != "" {
		s.emit(clean(s.line))
	}
	s.pending, s.line = "", ""
}
