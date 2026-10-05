package gate

import "testing"

func TestModelUsageInputOutputAccounting(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int64
	}{
		{`{"usage":{"input_tokens":4,"output_tokens":3}}`, 7},
		{`{"usage":{"prompt_tokens":4,"completion_tokens":3}}`, 7},
		{`{"usage":{"input_tokens":4,"output_tokens":3,"prompt_tokens":4,"completion_tokens":3}}`, 7},
		{`{"usage":{"input_tokens":4,"output_tokens":3,"input_tokens_details":{"cached_tokens":2},"output_tokens_details":{"reasoning_tokens":1}}}`, 7},
		{`{"usage":{"input_tokens":0,"output_tokens":0}}`, 0},
		{`{"usage":{"input_tokens":4}}`, -1},
		{`{"usage":{"total_tokens":7,"input_tokens":4}}`, -1},
		{`{"usage":{"total_tokens":1,"input_tokens":4,"output_tokens":3}}`, -1},
		{`{"usage":{"total_tokens":0,"input_tokens":-4,"output_tokens":4}}`, -1},
		{`{"usage":{"input_tokens":4,"output_tokens":3,"prompt_tokens":5,"completion_tokens":3}}`, -1},
		{`{"usage":{"input_tokens":9223372036854775807,"output_tokens":1}}`, -1},
		{`{"usage":{"total_tokens":9223372036854775807}}`, -1},
		{`{"usage":{}}`, -1},
	} {
		if got := modelUsage([]byte(tc.raw), false); got != tc.want {
			t.Errorf("%s: got %d want %d", tc.raw, got, tc.want)
		}
	}
}

func TestModelUsageRequiresTerminalAndHandlesCRLF(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int64
	}{
		{"data: {\"usage\":{\"total_tokens\":1}}\n\n", -1},
		{"data:{\"usage\":{\"total_tokens\":6}}\r\n\r\ndata: [DONE]\r\n\r\n", 6},
		{"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":4,\"output_tokens\":3}}}\n\n", 7},
		{"data: {\"choices\":[{\"delta\":{\"content\":\"usage\"}}]}\n\ndata: [DONE]\n\n", -1},
	} {
		if got := modelUsage([]byte(tc.raw), true); got != tc.want {
			t.Fatalf("usage %d want %d", got, tc.want)
		}
	}
}
