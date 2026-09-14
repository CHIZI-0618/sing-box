//go:build with_ebpf && (linux || android)

package ebpf

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const embeddedObjectPackage = "github.com/sagernet/sing-box/common/ebpf/internal/bpfgen"

// TestLibraryBoundary prevents the kernel mechanism package from acquiring a
// dependency on sing-box application code. internal/bpfgen remains part of the
// same ownership unit as the BPF sources and will move with this package when it
// becomes a standalone module.
func TestLibraryBoundary(t *testing.T) {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate eBPF package source")
	}
	packageDirectory := filepath.Dir(currentFile)
	entries, err := os.ReadDir(packageDirectory)
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(packageDirectory, name)
		parsed, parseErr := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Errorf("parse %s: %v", name, parseErr)
			continue
		}
		for _, importSpec := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(importSpec.Path.Value)
			if unquoteErr != nil {
				t.Errorf("parse import in %s: %v", name, unquoteErr)
				continue
			}
			if strings.HasPrefix(importPath, "github.com/sagernet/sing-box/") && importPath != embeddedObjectPackage {
				t.Errorf("%s imports sing-box application package %q", name, importPath)
			}
		}
	}
}
