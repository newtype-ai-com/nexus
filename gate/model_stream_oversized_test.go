package gate

import (
	"github.com/newtype-ai-com/nexus/internal/modelerror"
	"strings"
	"testing"
)

func TestM17OversizedExplicitErrorStaysFailed(t *testing.T) {
	data := "data: {\"error\":{\"code\":\"server_error\",\"message\":\"" + strings.Repeat("x", 65536) + "\"}}\n"
	for _, event := range []string{"error", "response.failed"} {
		for _, raw := range []string{"event: " + event + "\n" + data + "\n", data + "event: " + event + "\n\n"} {
			for _, size := range []int{1, 32768} {
				raw := raw
				count := 0
				o := modelErrorObserver{sse: true, report: func(d modelerror.Detail) {
					count++
					if d != (modelerror.Detail{}) {
						t.Fatal("oversized details retained", d)
					}
				}}
				for len(raw) > 0 {
					n := size
					if n > len(raw) {
						n = len(raw)
					}
					o.write([]byte(raw[:n]))
					raw = raw[n:]
				}
				o.end()
				if !o.failed || count != 1 {
					t.Fatal("explicit error lost", o.failed, count)
				}
			}
		}
	}
}
