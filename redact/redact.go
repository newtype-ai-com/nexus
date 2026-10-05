// Package redact removes recognizable secrets before text enters a ledger.
// This is defense in depth, not a guarantee that arbitrary unknown secrets can
// be detected. Secret values must remain outside prompts and event payloads.
package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
)

type pattern struct {
	kind string
	re   *regexp.Regexp
}

func p(kind, expression string) pattern { return pattern{kind, regexp.MustCompile(expression)} }

var patterns = []pattern{
	p("private_key", `(?s)-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----`),
	p("nts_licence", `\bntl_[A-Za-z0-9]{16,}`),
	p("nts_login", `\bntg_[A-Za-z0-9_\-]{16,}`),
	p("enrol_poll", `\benp_[A-Za-z0-9_\-]{16,}`),
	p("enrol_verify", `\bvfy_[A-Za-z0-9_\-]{16,}`),
	p("user_approval", `\buap_[A-Za-z0-9_\-]{16,}`),
	p("nts_bootstrap", `\bntb_[A-Za-z0-9_\-]{16,}`),
	p("nts_agent", `\bnta_[A-Za-z0-9_\-]{16,}`),
	p("anthropic_key", `\bsk-ant-[A-Za-z0-9_\-]{20,}`),
	p("openai_key", `\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}`),
	p("github_token", `\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})`),
	p("slack_token", `\bxox[abprs]-[A-Za-z0-9\-]{10,}`),
	p("aws_access_key", `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	p("google_api_key", `\bAIza[0-9A-Za-z0-9_\-]{35}`),
	p("resend_key", `\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}`),
	p("jwt", `\beyJ[A-Za-z0-9_\-]{7,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
	p("bearer_token", `(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{20,}=*`),
	p("password", `(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["']?[^\s"']{8,}`),
	p("card_number", `\b[0-9](?:[ -]?[0-9]){12,18}\b`),
}
var placeholder = regexp.MustCompile(`\[secret:[a-z_]+\]`)

type span struct {
	start, end int
	kind       string
}

func luhn(text string) bool {
	digits := []int{}
	for _, r := range text {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	for i := len(digits) - 1; i >= 0; i-- {
		n := digits[i]
		if (len(digits)-1-i)%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

// Text gives earlier patterns precedence over overlapping generic matches.
func Text(text string) (string, int) {
	spans := []span{}
	for _, loc := range placeholder.FindAllStringIndex(text, -1) {
		spans = append(spans, span{loc[0], loc[1], ""})
	}
	count := 0
	for _, pattern := range patterns {
		for _, loc := range pattern.re.FindAllStringIndex(text, -1) {
			if pattern.kind == "card_number" && !luhn(text[loc[0]:loc[1]]) {
				continue
			}
			overlap := false
			for _, s := range spans {
				if loc[0] < s.end && s.start < loc[1] {
					overlap = true
					break
				}
			}
			if overlap {
				continue
			}
			spans = append(spans, span{loc[0], loc[1], pattern.kind})
			count++
		}
	}
	if count == 0 {
		return text, 0
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var out strings.Builder
	end := 0
	for _, s := range spans {
		out.WriteString(text[end:s.start])
		if s.kind == "" {
			out.WriteString(text[s.start:s.end])
		} else {
			out.WriteString("[secret:" + s.kind + "]")
		}
		end = s.end
	}
	out.WriteString(text[end:])
	return out.String(), count
}

// Fingerprints reports every recognizable secret in text as a count per
// "kind:sha256(match)" key; it never returns the matched text itself. Unlike
// Text it applies no precedence between overlapping patterns: every pattern's
// own matches count, so a new secret cannot hide inside (or by extending) an
// existing match of another kind. Only a match lying wholly inside a
// "[secret:kind]" placeholder is ignored. Comparing two texts' fingerprints by
// count tells whether the second contains a match the first did not have; a
// secret that only moved keeps its key, while any change to a matched span
// (one character, an extension, a merge of two spans) yields a new key.
func Fingerprints(text string) map[string]int {
	out := map[string]int{}
	holders := placeholder.FindAllStringIndex(text, -1)
	for _, pattern := range patterns {
		for _, loc := range pattern.re.FindAllStringIndex(text, -1) {
			match := text[loc[0]:loc[1]]
			if pattern.kind == "card_number" && !luhn(match) {
				continue
			}
			inside := false
			for _, h := range holders {
				if h[0] <= loc[0] && loc[1] <= h[1] {
					inside = true
					break
				}
			}
			if inside {
				continue
			}
			sum := sha256.Sum256([]byte(match))
			out[pattern.kind+":"+hex.EncodeToString(sum[:])]++
		}
	}
	return out
}

// Introduced reports whether after holds a recognizable secret that before did
// not: a fingerprint absent from before, or present more often than before.
func Introduced(before, after string) bool {
	old := Fingerprints(before)
	for key, n := range Fingerprints(after) {
		if n > old[key] {
			return true
		}
	}
	return false
}

// JSON redacts string values AND object keys without rounding JSON numbers.
// Duplicate object keys and redacted-key collisions fail closed rather than
// silently dropping or overwriting fields. Invalid JSON is never persisted.
func JSON(payload []byte) ([]byte, int, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	value, count, err := readValue(decoder)
	if err != nil {
		return nil, 0, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, 0, errors.New("expected one JSON value")
	}
	clean, err := json.Marshal(value)
	return clean, count, err
}
func readValue(d *json.Decoder) (any, int, error) {
	token, err := d.Token()
	if err != nil {
		return nil, 0, err
	}
	switch v := token.(type) {
	case string:
		text, n := Text(v)
		return text, n, nil
	case json.Delim:
		count := 0
		if v == '{' {
			object := map[string]any{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return nil, 0, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, 0, errors.New("invalid JSON key")
				}
				key, n := Text(key)
				count += n
				if _, exists := object[key]; exists {
					return nil, 0, errors.New("duplicate or redacted JSON key collision")
				}
				val, n, err := readValue(d)
				if err != nil {
					return nil, 0, err
				}
				count += n
				object[key] = val
			}
			close, err := d.Token()
			if err != nil || close != json.Delim('}') {
				return nil, 0, errors.New("invalid JSON object")
			}
			return object, count, nil
		}
		if v == '[' {
			array := []any{}
			for d.More() {
				val, n, err := readValue(d)
				if err != nil {
					return nil, 0, err
				}
				count += n
				array = append(array, val)
			}
			close, err := d.Token()
			if err != nil || close != json.Delim(']') {
				return nil, 0, errors.New("invalid JSON array")
			}
			return array, count, nil
		}
		return nil, 0, errors.New("unexpected JSON delimiter")
	default:
		return token, 0, nil
	}
}
