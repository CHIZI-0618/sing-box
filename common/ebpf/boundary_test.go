//go:build with_ebpf && (linux || android)

package ebpf

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const mechanismPackage = "github.com/sagernet/sing-box/common/ebpf"

// TestLibraryBoundary prevents the kernel mechanism package from acquiring a
// dependency on sing-box application code. The complete source tree is checked,
// including tests and nested tools, because they must move with the package.
// Self-imports below common/ebpf remain part of the same ownership unit as the
// BPF sources and will be rewritten with the module path during extraction.
func TestLibraryBoundary(t *testing.T) {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate eBPF package source")
	}
	packageDirectory := filepath.Dir(currentFile)
	fileSet := token.NewFileSet()
	err := filepath.WalkDir(packageDirectory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		name, relativeErr := filepath.Rel(packageDirectory, path)
		if relativeErr != nil {
			return relativeErr
		}
		parsed, parseErr := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Errorf("parse %s: %v", name, parseErr)
			return nil
		}
		for _, importSpec := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(importSpec.Path.Value)
			if unquoteErr != nil {
				t.Errorf("parse import in %s: %v", name, unquoteErr)
				continue
			}
			if strings.HasPrefix(importPath, "github.com/sagernet/sing-box/") &&
				importPath != mechanismPackage && !strings.HasPrefix(importPath, mechanismPackage+"/") {
				t.Errorf("%s imports sing-box application package %q", name, importPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
