package gate

import (
	"bytes"

	"github.com/newtype-ai-com/nexus/internal/modelerror"
)

// Observes in parallel with relay, retaining at most one bounded event. An
// oversized line/event is discarded until the next blank line. No tail search,
// goroutine, provider body logging, or unbounded buffering is involved.
type modelErrorObserver struct {
	sse                           bool
	line, data                    []byte
	event                         string
	discard, lineOverflow, failed bool
	report                        func(modelerror.Detail)
}

func (o *modelErrorObserver) write(p []byte) {
	if o.failed {
		return
	}
	if !o.sse {
		if len(o.data)+len(p) > modelerror.MaxEnvelope {
			o.discard = true
			o.data = nil
		}
		if !o.discard {
			o.data = append(o.data, p...)
		}
		return
	}
	for _, c := range p {
		if c == '\n' {
			o.finishLine()
			if o.failed {
				return
			}
			continue
		}
		if len(o.line) == modelerror.MaxEnvelope {
			o.lineOverflow = true
			o.discard = true
		}
		if !o.lineOverflow {
			o.line = append(o.line, c)
		}
	}
}
func (o *modelErrorObserver) finishLine() {
	line := bytes.TrimSuffix(o.line, []byte{'\r'})
	if len(line) == 0 && !o.lineOverflow {
		o.inspect()
		o.data, o.event, o.discard = nil, "", false
	} else if !o.lineOverflow {
		// Preserve an explicit error event name even when its data was too
		// large, including event: fields appearing after the data fields.
		if bytes.HasPrefix(line, []byte("event:")) {
			name := bytes.TrimSpace(line[6:])
			if bytes.Equal(name, []byte("error")) || bytes.Equal(name, []byte("response.failed")) {
				o.event = string(name)
			} else {
				o.event = ""
			}
		} else if !o.discard && bytes.HasPrefix(line, []byte("data:")) {
			data := bytes.TrimPrefix(line[5:], []byte{' '})
			if len(o.data)+len(data)+1 > modelerror.MaxEnvelope {
				o.discard = true
				o.data = nil
			} else {
				o.data = append(o.data, data...)
				o.data = append(o.data, '\n')
			}
		}
	}
	o.line, o.lineOverflow = o.line[:0], false
}
func (o *modelErrorObserver) inspect() {
	if o.failed {
		return
	}
	if o.discard {
		if o.event == "error" || o.event == "response.failed" {
			o.failed = true
			o.report(modelerror.Detail{})
		}
		return
	}
	if modelerror.IsEvent(o.data, o.event) {
		o.failed = true
		o.report(modelerror.Parse(o.data))
	}
}
func (o *modelErrorObserver) end() {
	if o.sse && (len(o.line) != 0 || o.lineOverflow) {
		o.finishLine()
	}
	o.inspect()
}
