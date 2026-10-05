package core

import (
	"errors"
	"path/filepath"
	"strings"
)

// NormalizeActiveFiles validates advisory names without opening any target.
// A malformed nonempty list is an error, never converted to unknown scope.
func NormalizeActiveFiles(workDir string, files []string) ([]string, error) {
	if len(files) > 128 {
		return nil, errors.New("too many active files")
	}
	base, err := filepath.Abs(workDir)
	if err != nil {
		return nil, errors.New("invalid active file workspace")
	}
	var result []string
	seen := map[string]bool{}
	for _, file := range files {
		if file == "" || len(file) > 4096 || strings.ContainsRune(file, 0) {
			return nil, errors.New("invalid active file")
		}
		if filepath.IsAbs(file) {
			file, err = filepath.Rel(base, file)
			if err != nil {
				return nil, errors.New("active file outside workspace")
			}
		}
		file = filepath.Clean(file)
		if !filepath.IsLocal(file) || file == "." {
			return nil, errors.New("active file outside workspace")
		}
		file = filepath.ToSlash(file)
		if strings.ContainsAny(file, "\\:\r\n") {
			return nil, errors.New("invalid active file")
		}
		if !seen[file] {
			result = append(result, file)
			seen[file] = true
		}
	}
	return result, nil
}
