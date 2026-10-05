package secretplan

import (
	"sort"
	"strings"
)

// Execution closure (schema ruling §2): plan/3 names every code root the
// program may load from as a content-addressed directory manifest, a typed
// import policy and a typed cwd. The plan carries only the manifests'
// digests; the manifests themselves are pinned files in their own format
// (DirectoryManifestVersion) so a stdlib inventory need not fit the plan's
// 64-entry/64-KiB bounds. The executor verifies the filesystem against them
// before Start and again at launch; same-UID replacement between check and
// use stays outside the claim.

const (
	DirectoryManifestVersion = "newtype.directory-manifest/1"
	ImportPolicyVersion      = "newtype.import-policy/1"
	ImplementationCPython    = "cpython"

	MaxDirectoryManifests  = 16
	MaxModuleRoots         = 16
	MaxManifestBytes       = 8 << 20
	MaxManifestEntries     = 20000
	MaxManifestDepth       = 32
	MaxManifestTotalBytes  = int64(1) << 30
	MaxManifestRelativeLen = 1024
)

// DirectoryRef is one plan entry: a root and the pinned manifest describing it.
type DirectoryRef struct {
	Root, ManifestPath, ManifestSHA256 string
}

// ImportPolicy is the typed closure of a CPython program.
type ImportPolicy struct {
	Implementation string
	Interpreter    string   // the actual executable (never a launcher stub)
	Bootstrap      string   // the pinned entry run before any A/product module
	StdlibRoot     string   // covered by a directory manifest
	ModuleRoots    []string // ordered sys.path, each covered by a directory manifest
}

// closureV3 parses directory_manifests, import_policy and the typed cwd.
func closureV3(m map[string]any, p *Plan) error {
	list, ok := m["directory_manifests"].([]any)
	if !ok || len(list) < 1 || len(list) > MaxDirectoryManifests {
		return Error("directory_manifests")
	}
	byRoot := map[string]DirectoryRef{}
	for _, v := range list {
		o, ok := obj(v)
		if !ok || !exact(o, "root", "manifest_path", "manifest_sha256") {
			return Error("directory_manifests")
		}
		var d DirectoryRef
		var a, b, c bool
		d.Root, a = str(o["root"])
		d.ManifestPath, b = str(o["manifest_path"])
		d.ManifestSHA256, c = str(o["manifest_sha256"])
		if !a || !b || !c || !absPath(d.Root) || !absPath(d.ManifestPath) || !reSHA.MatchString(d.ManifestSHA256) {
			return Error("directory_manifests")
		}
		if under(d.ManifestPath, d.Root) {
			return Error("directory_manifests") // a manifest never describes its own directory
		}
		for r := range byRoot {
			if r == d.Root || under(r, d.Root) || under(d.Root, r) {
				return Error("directory_overlap")
			}
		}
		byRoot[d.Root] = d
		p.DirectoryManifests = append(p.DirectoryManifests, d)
	}
	ip, ok := obj(m["import_policy"])
	if !ok || !exact(ip, "version", "implementation", "interpreter", "bootstrap", "stdlib_root", "module_roots") || ip["version"] != ImportPolicyVersion {
		return Error("import_policy")
	}
	var pol ImportPolicy
	var a, b, c, d bool
	pol.Implementation, a = str(ip["implementation"])
	pol.Interpreter, b = str(ip["interpreter"])
	pol.Bootstrap, c = str(ip["bootstrap"])
	pol.StdlibRoot, d = str(ip["stdlib_root"])
	if !a || !b || !c || !d || pol.Implementation != ImplementationCPython || !absPath(pol.Interpreter) || !absPath(pol.Bootstrap) || !absPath(pol.StdlibRoot) {
		return Error("import_policy")
	}
	pol.ModuleRoots, ok = strs(m["import_policy"].(map[string]any)["module_roots"])
	if !ok || len(pol.ModuleRoots) > MaxModuleRoots {
		return Error("import_policy")
	}
	if _, ok := byRoot[pol.StdlibRoot]; !ok {
		return Error("import_closure") // the stdlib must be manifest-covered
	}
	seen := map[string]bool{}
	for _, r := range pol.ModuleRoots {
		if _, ok := byRoot[r]; !ok || seen[r] || !absPath(r) {
			return Error("import_closure")
		}
		seen[r] = true
	}
	// the program's interpreter is the verified executable itself
	if p.Interpreter != pol.Interpreter {
		return Error("import_interpreter")
	}
	// bootstrap and script live inside declared module roots
	if !insideAny(pol.Bootstrap, pol.ModuleRoots) || !insideAny(p.Script, pol.ModuleRoots) {
		return Error("import_closure")
	}
	p.ImportPolicy = pol
	cw, ok := obj(m["cwd"])
	if !ok || !exact(cw, "path", "directory_manifest_sha256") {
		return Error("cwd")
	}
	path, a := str(cw["path"])
	sha, b := str(cw["directory_manifest_sha256"])
	ref, okr := byRoot[path]
	if !a || !b || !absPath(path) || !okr || ref.ManifestSHA256 != sha {
		return Error("cwd")
	}
	p.Cwd, p.CwdManifestSHA256 = path, sha
	return nil
}

func under(path, root string) bool { return strings.HasPrefix(path, root+"/") }

func insideAny(path string, roots []string) bool {
	for _, r := range roots {
		if under(path, r) {
			return true
		}
	}
	return false
}

// ---- directory manifest file format -------------------------------------------------

// ManifestEntry is one filesystem entry under a root.
type ManifestEntry struct {
	Path   string // relative, '/'-separated, canonical
	Type   string // "file" | "dir"
	Mode   int64  // permission bits (0..0o7777); files and directories
	Size   int64  // files only
	SHA256 string // files only
}

// DirectoryManifest is a parsed newtype.directory-manifest/1.
type DirectoryManifest struct {
	Root    string
	Entries []ManifestEntry
	Total   int64
}

// ParseDirectoryManifest checks one manifest's canonical bytes: canonical
// JSON (secretplan rules, but with the manifest's own size/entry bounds),
// exact keys, sorted unique entries, canonical relative paths with every
// parent directory listed, no case-colliding paths, bounded depth and total.
func ParseDirectoryManifest(raw []byte) (DirectoryManifest, error) {
	var out DirectoryManifest
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return out, Error("manifest_size")
	}
	v, err := parseBounded(raw, MaxManifestBytes, MaxManifestEntries+8)
	if err != nil {
		return out, err
	}
	m, ok := obj(v)
	if !ok || !exact(m, "version", "root", "entries") || m["version"] != DirectoryManifestVersion {
		return out, Error("manifest_keys")
	}
	out.Root, ok = str(m["root"])
	if !ok || !absPath(out.Root) {
		return out, Error("manifest_root")
	}
	list, ok := m["entries"].([]any)
	if !ok || len(list) > MaxManifestEntries {
		return out, Error("manifest_entries")
	}
	seen, folded := map[string]string{}, map[string]bool{}
	prev := ""
	for i, ev := range list {
		e, ok := obj(ev)
		if !ok {
			return out, Error("manifest_entry")
		}
		var x ManifestEntry
		var a, b, c bool
		x.Path, a = str(e["path"])
		x.Type, b = str(e["type"])
		x.Mode, c = num(e["mode"])
		if !a || !b || !c || x.Mode < 0 || x.Mode > 0o7777 || !relPath(x.Path) {
			return out, Error("manifest_entry")
		}
		switch x.Type {
		case "file":
			if !exact(e, "path", "type", "mode", "size", "sha256") {
				return out, Error("manifest_entry")
			}
			x.Size, a = num(e["size"])
			x.SHA256, b = str(e["sha256"])
			if !a || !b || x.Size < 0 || !reSHA.MatchString(x.SHA256) {
				return out, Error("manifest_entry")
			}
			out.Total += x.Size
			if out.Total > MaxManifestTotalBytes {
				return out, Error("manifest_total")
			}
		case "dir":
			if !exact(e, "path", "type", "mode") {
				return out, Error("manifest_entry")
			}
		default:
			return out, Error("manifest_entry") // no symlinks or special files
		}
		if i > 0 && !(prev < x.Path) {
			return out, Error("manifest_order") // sorted, unique
		}
		prev = x.Path
		low := strings.ToLower(x.Path)
		if folded[low] {
			return out, Error("manifest_case") // case-colliding entries
		}
		folded[low] = true
		if j := strings.LastIndexByte(x.Path, '/'); j >= 0 {
			if seen[x.Path[:j]] != "dir" {
				return out, Error("manifest_parent") // every parent is a listed directory
			}
		}
		seen[x.Path] = x.Type
		out.Entries = append(out.Entries, x)
	}
	return out, nil
}

// relPath: canonical relative path, '/'-separated, bounded depth.
func relPath(s string) bool {
	if s == "" || len(s) > MaxManifestRelativeLen || strings.HasPrefix(s, "/") || !reAbsChars.MatchString("/"+s) {
		return false
	}
	parts := strings.Split(s, "/")
	if len(parts) > MaxManifestDepth {
		return false
	}
	for _, c := range parts {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// EncodeDirectoryManifest produces the canonical bytes for root/entries
// (entries are sorted here); a generator and the tests use it.
func EncodeDirectoryManifest(root string, entries []ManifestEntry) []byte {
	es := append([]ManifestEntry(nil), entries...)
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
	list := make([]any, 0, len(es))
	for _, e := range es {
		o := map[string]any{"path": e.Path, "type": e.Type, "mode": e.Mode}
		if e.Type == "file" {
			o["size"], o["sha256"] = e.Size, e.SHA256
		}
		list = append(list, o)
	}
	return Encode(map[string]any{"version": DirectoryManifestVersion, "root": root, "entries": list})
}
