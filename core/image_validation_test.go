package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

func inlineImage(mime string, data []byte) Image {
	return Image{URL: "data:image/" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)}
}

func imageFixtures(t *testing.T) map[string][]byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 3))
	fixtures := make(map[string][]byte)
	for _, mime := range []string{"png", "jpeg", "gif"} {
		var b bytes.Buffer
		var err error
		switch mime {
		case "png":
			err = png.Encode(&b, img)
		case "jpeg":
			err = jpeg.Encode(&b, img, nil)
		case "gif":
			err = gif.Encode(&b, img, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		fixtures[mime] = b.Bytes()
	}
	// A small lossy WebP, kept inline because x/image provides no encoder.
	webp, err := base64.StdEncoding.DecodeString("UklGRiIAAABXRUJQVlA4IBYAAAAwAQCdASoBAAEADsD+JaQAA3AAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	fixtures["webp"] = webp
	return fixtures
}

func TestInlineImageHeaders(t *testing.T) {
	fixtures := imageFixtures(t)
	for mime, raw := range fixtures {
		t.Run(mime, func(t *testing.T) {
			if err := ValidateImages([]Image{inlineImage(mime, raw)}); err != nil {
				t.Fatal(err)
			}
			for declared := range fixtures {
				if declared != mime && ValidateImages([]Image{inlineImage(declared, raw)}) == nil {
					t.Errorf("accepted %s as %s", mime, declared)
				}
			}
			for _, bad := range [][]byte{nil, []byte("private-not-an-image"), raw[:8]} {
				err := ValidateImages([]Image{inlineImage(mime, bad)})
				if err == nil || strings.Contains(err.Error(), "private-not-an-image") {
					t.Fatalf("bad header accepted or leaked: %v", err)
				}
			}
		})
	}
	zeroGIF := bytes.Clone(fixtures["gif"])
	binary.LittleEndian.PutUint16(zeroGIF[6:8], 0)
	if ValidateImages([]Image{inlineImage("gif", zeroGIF)}) == nil {
		t.Fatal("zero width accepted")
	}
}

func TestInlineImageAggregateLimits(t *testing.T) {
	raw := imageFixtures(t)["png"]
	// Only headers are inspected: trailing data counts toward the byte budget.
	padded := append(bytes.Clone(raw), make([]byte, MaxImageBytes-len(raw))...)
	if err := ValidateImages([]Image{inlineImage("png", padded)}); err != nil {
		t.Fatal("exact byte limit:", err)
	}
	if err := ValidateImages([]Image{inlineImage("png", padded), inlineImage("png", raw)}); err == nil || err.Error() != "images exceed 5 MiB" {
		t.Fatal("aggregate byte limit:", err)
	}
	images := make([]Image, 16)
	for i := range images {
		images[i] = inlineImage("png", raw)
	}
	if err := ValidateImages(images); err != nil {
		t.Fatal("exact count limit:", err)
	}
	if ValidateImages(append(images, images[0])) == nil {
		t.Fatal("image count limit not enforced")
	}
}

func TestInvalidImageRejectedBeforeTurn(t *testing.T) {
	calls := 0
	e := newTestEngine(t, modelFunc(func(_ context.Context, _ ModelRequest, _ func(string)) (ModelResponse, error) {
		calls++
		return ModelResponse{Content: "ok"}, nil
	}), nil)
	ch, err := e.SendMessage(ChatRequest{SessionID: "images", Message: "describe", Images: []Image{inlineImage("png", []byte("private-not-an-image"))}})
	if err == nil || ch != nil {
		t.Fatal("invalid image started a turn")
	}
	if _, err := e.LoadSession("images"); err == nil {
		t.Fatal("rejected request persisted a session")
	}
	send(t, e, ChatRequest{SessionID: "images", Message: "normal turn"})
	if calls != 1 {
		t.Fatalf("model calls = %d; want only the normal turn", calls)
	}
}
