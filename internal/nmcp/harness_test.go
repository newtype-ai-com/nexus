package nmcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/core"
	"github.com/newtype-ai-com/nexus/internal/nexusops"
	"github.com/newtype-ai-com/nexus/internal/nexusops/nexusopstest"
	"github.com/newtype-ai-com/nexus/nexus"
)

// seatRoot mirrors cmd/newtype nmcpRoot (tool-only + session:delegate one level).
var seatRoot = nexusops.Root{Scope: []string{"session:delegate"}, Limits: nexus.Limits{MaxDepth: 1}}

func attach(t *testing.T, f *nexusopstest.Fake, name string, root nexusops.Root) *nexusops.Contract {
	t.Helper()
	seat, err := nexusops.Attach(context.Background(), f.Identity(), name, nexusops.Options{Transport: f.Transport(), Root: root, AlwaysIssue: true})
	if err != nil {
		t.Fatal(err)
	}
	return &nexusops.Contract{Seat: seat, Record: true, Poll: 20 * time.Millisecond}
}

// client drives a Server over in-memory pipes like an MCP host would.
type client struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *bufio.Reader
	next atomic.Int64
	done chan error
}

func startServer(t *testing.T, tools Caller) *client {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	srv := &Server{Tools: tools, Name: "newtype-nexus", Version: "test", Diag: io.Discard}
	c := &client{t: t, in: inW, out: bufio.NewReader(outR), done: make(chan error, 1)}
	go func() { c.done <- srv.Serve(context.Background(), inR, outW); outW.Close() }()
	t.Cleanup(func() { inW.Close(); <-c.done })
	return c
}

func (c *client) send(raw string) {
	c.t.Helper()
	if _, err := io.WriteString(c.in, raw+"\n"); err != nil {
		c.t.Fatal(err)
	}
}

type response struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *client) read() response {
	c.t.Helper()
	line, err := c.out.ReadBytes('\n')
	if err != nil {
		c.t.Fatal(err)
	}
	var r response
	if err := json.Unmarshal(line, &r); err != nil {
		c.t.Fatalf("not JSON-RPC: %q", line)
	}
	return r
}

func (c *client) request(method string, params any) response {
	c.t.Helper()
	c.sendRequest(method, params)
	return c.read()
}

func (c *client) sendRequest(method string, params any) int64 {
	c.t.Helper()
	id := c.next.Add(1)
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	c.send(string(raw))
	return id
}

func (c *client) initialize() {
	c.t.Helper()
	r := c.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "fixture", "version": "1"}})
	if r.Error != nil {
		c.t.Fatalf("initialize: %+v", r.Error)
	}
	c.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

// outcome is the path-independent view of one tool call.
type outcome struct {
	IsError bool
	Code    string
	Text    string
}

func (c *client) tool(name string, args string) outcome {
	c.t.Helper()
	r := c.request("tools/call", map[string]any{"name": name, "arguments": json.RawMessage(args)})
	if r.Error != nil {
		c.t.Fatalf("%s: protocol error %+v", name, r.Error)
	}
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil || len(res.Content) != 1 || res.Content[0].Type != "text" {
		c.t.Fatalf("%s: result %s", name, r.Result)
	}
	return mkOutcome(res.Content[0].Text, res.IsError)
}

func mkOutcome(text string, isErr bool) outcome {
	o := outcome{IsError: isErr, Text: text}
	if isErr {
		var e nexusops.ToolError
		_ = json.Unmarshal([]byte(text), &e)
		o.Code = e.Code
	}
	return o
}

// engine runs the same tool through the engine path (core.Tool.Run).
func engine(t *testing.T, c *nexusops.Contract, name, args string) outcome {
	t.Helper()
	for _, tool := range c.Tools() {
		if tool.Spec.Name == name {
			text, err := tool.Run(context.Background(), core.ToolContext{}, json.RawMessage(args))
			if err != nil {
				return mkOutcome(err.Error(), true)
			}
			return mkOutcome(text, false)
		}
	}
	t.Fatalf("engine has no %s", name)
	return outcome{}
}

func contains(o outcome, s string) bool { return strings.Contains(o.Text, s) }
