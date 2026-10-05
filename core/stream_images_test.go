package core

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestImagesBudgetAndIsolation(t *testing.T) {
	image := inlineImage("png", imageFixtures(t)["png"])
	for _, images := range [][]Image{{image}, {{URL: "https://example.test/image.png"}}} {
		if err := ValidateImages(images); err != nil {
			t.Fatal(err)
		}
	}
	for _, images := range [][]Image{{{URL: "file:///etc/passwd"}}, {{URL: "data:text/html;base64,aGk="}}, {{URL: "data:image/png;base64,???"}}, {{URL: "https://user:pass@example.test/i"}}, {{URL: "data:image/png;base64," + base64.StdEncoding.EncodeToString(make([]byte, MaxImageBytes+1))}}} {
		if ValidateImages(images) == nil {
			t.Fatal("invalid image accepted")
		}
	}
	e := newTestEngine(t, modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
		if len(r.Messages[len(r.Messages)-1].Images) != 1 {
			t.Error("missing image")
		}
		return ModelResponse{Content: "ok"}, nil
	}), nil)
	events := send(t, e, ChatRequest{SessionID: "images", Message: "describe", Images: []Image{image}})
	if strings.Contains(eventText(events), "base64") {
		t.Fatal("image in events")
	}
	record, _ := e.LoadSession("images")
	if len(record.Turns) != 1 {
		t.Fatal("missing turn")
	}
}

func TestVisibleStreamEveryBoundary(t *testing.T) {
	text := "첫줄\n<think>never reveal\nprivate</think>둘째줄\nsk-" + strings.Repeat("x", 25) + "\n끝"
	want := "첫줄\n둘째줄\n[secret:openai_key]\n끝"
	for width := 1; width <= len(text); width++ {
		var got strings.Builder
		s := visibleStream{emit: func(s string) { got.WriteString(s) }}
		for i := 0; i < len(text); i += width {
			s.write(text[i:min(len(text), i+width)])
		}
		s.finish()
		if got.String() != want {
			t.Fatalf("width %d: %q", width, got.String())
		}
	}
}
func TestStreamVisibleBeforeModelCompletes(t *testing.T) {
	release := make(chan struct{})
	e := newTestEngine(t, modelFunc(func(ctx context.Context, _ ModelRequest, on func(string)) (ModelResponse, error) {
		on("진행 중\n")
		select {
		case <-release:
		case <-ctx.Done():
			return ModelResponse{}, ctx.Err()
		}
		on("완료")
		return ModelResponse{Content: "진행 중\n완료"}, nil
	}), nil)
	ch, err := e.SendMessage(ChatRequest{Message: "test"})
	if err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case ev := <-ch:
			if ev.Type == "content_delta" {
				close(release)
				rest := collect(t, ch)
				if !strings.Contains(eventText(rest), "완료") {
					t.Fatal("missing final")
				}
				return
			}
		case <-timer.C:
			e.Cancel()
			t.Fatal("stream buffered until completion")
		}
	}
}
