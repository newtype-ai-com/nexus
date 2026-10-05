package secretplan

import (
	"strings"
	"testing"
)

func fxEntries() []ManifestEntry {
	return []ManifestEntry{
		{Path: "a", Type: "dir", Mode: 0o755},
		{Path: "a/caller.py", Type: "file", Mode: 0o644, Size: 10, SHA256: fxSHA},
		{Path: "bootstrap.py", Type: "file", Mode: 0o644, Size: 5, SHA256: fxSHA},
	}
}

func TestDirectoryManifest(t *testing.T) {
	raw := EncodeDirectoryManifest("/fixture/a", fxEntries())
	m, err := ParseDirectoryManifest(raw)
	if err != nil || m.Root != "/fixture/a" || len(m.Entries) != 3 || m.Total != 15 {
		t.Fatalf("%+v %v", m, err)
	}
	bad := map[string][]ManifestEntry{
		"symlink type":     {{Path: "x", Type: "symlink", Mode: 0o777}},
		"absolute path":    {{Path: "/x", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}},
		"dot component":    {{Path: "./x", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}},
		"dotdot component": {{Path: "a/../x", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}},
		"missing parent":   {{Path: "a/x", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}},
		"parent is a file": {{Path: "a", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}, {Path: "a/x", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}},
		"case collision":   {{Path: "A", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}, {Path: "a", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}},
		"duplicate":        {{Path: "x", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}, {Path: "x", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}},
		"bad mode":         {{Path: "x", Type: "file", Mode: 0o10000, Size: 1, SHA256: fxSHA}},
		"negative size":    {{Path: "x", Type: "file", Mode: 0o644, Size: -1, SHA256: fxSHA}},
		"bad sha":          {{Path: "x", Type: "file", Mode: 0o644, Size: 1, SHA256: "x"}},
		"too deep":         {{Path: strings.Repeat("d/", 32) + "x", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}},
		"total over 1 GiB": {{Path: "x", Type: "file", Mode: 0o644, Size: MaxManifestTotalBytes, SHA256: fxSHA}, {Path: "y", Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA}},
	}
	for name, es := range bad {
		if _, err := ParseDirectoryManifest(EncodeDirectoryManifest("/fixture/a", es)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// unsorted bytes, extra keys, size fields on a directory, root spelling, version
	for name, b := range map[string]string{
		"unsorted":       strings.Replace(string(raw), `"path":"a"`, `"path":"zz"`, 1),
		"dir with size":  strings.Replace(string(raw), `"mode":493,"path":"a","type":"dir"`, `"mode":493,"path":"a","size":0,"type":"dir"`, 1),
		"root dot":       strings.Replace(string(raw), `"root":"/fixture/a"`, `"root":"/fixture/./a"`, 1),
		"version 2":      strings.Replace(string(raw), DirectoryManifestVersion, "newtype.directory-manifest/2", 1),
		"not canonical":  strings.Replace(string(raw), `":`, `": `, 1),
		"trailing bytes": string(raw) + " ",
	} {
		if _, err := ParseDirectoryManifest([]byte(b)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// the manifest format allows more than the plan's 64-entry collections
	many := []ManifestEntry{}
	for i := 0; i < 300; i++ {
		many = append(many, ManifestEntry{Path: "m" + strings.Repeat("0", 3-len(itoa(i))) + itoa(i), Type: "file", Mode: 0o644, Size: 1, SHA256: fxSHA})
	}
	if _, err := ParseDirectoryManifest(EncodeDirectoryManifest("/fixture/a", many)); err != nil {
		t.Fatal(err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}
