package core

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/url"
	"strings"

	"golang.org/x/image/webp"
)

// Image carries an explicit HTTPS URL or an inline image data URL. The engine
// never fetches URLs itself; callers must authorize sending images to a model.
// Image bytes are not persisted in the session ledger or emitted as events.
type Image struct {
	URL string `json:"url"`
}

const MaxImageBytes = 5 * 1024 * 1024

// ValidateImages checks inline image headers and their declared MIME types, and
// applies a 5 MiB total inline budget before any model call. It does not decode
// pixels or validate the complete payload, and never fetches external URLs.
func ValidateImages(images []Image) error {
	if len(images) > 16 {
		return errors.New("at most 16 images are allowed")
	}
	total := 0
	for _, img := range images {
		if strings.HasPrefix(img.URL, "data:") {
			header, data, ok := strings.Cut(img.URL, ",")
			if !ok {
				return errors.New("invalid image data URL")
			}
			var decodeConfig func(io.Reader) (image.Config, error)
			switch header {
			case "data:image/png;base64":
				decodeConfig = png.DecodeConfig
			case "data:image/jpeg;base64":
				decodeConfig = jpeg.DecodeConfig
			case "data:image/webp;base64":
				decodeConfig = webp.DecodeConfig
			case "data:image/gif;base64":
				decodeConfig = gif.DecodeConfig
			default:
				return errors.New("unsupported image MIME type")
			}
			if len(data) > base64.StdEncoding.EncodedLen(MaxImageBytes) {
				return errors.New("images exceed 5 MiB")
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(data)
			if err != nil || len(decoded) == 0 {
				return errors.New("invalid image base64")
			}
			total += len(decoded)
			if total > MaxImageBytes {
				return errors.New("images exceed 5 MiB")
			}
			config, err := decodeConfig(bytes.NewReader(decoded))
			if err != nil || config.Width <= 0 || config.Height <= 0 {
				// Decoder errors can contain input details; expose only a class.
				return errors.New("invalid image header or MIME mismatch")
			}
		} else {
			u, err := url.Parse(img.URL)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(img.URL) > 8192 {
				return errors.New("image must be an explicit HTTPS or image data URL")
			}
		}
	}
	return nil
}
