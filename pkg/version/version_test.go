package version

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionInfo(t *testing.T) {
	if Version == "" {
		t.Fatal("Version should not be empty")
	}

	info := Get()
	if info.Version != Version {
		t.Errorf("Expected info.Version=%s, got %s", Version, info.Version)
	}

	str := String()
	if str == "" || strings.HasPrefix(str, "v") {
		t.Errorf("Expected normalized version string, got %s", str)
	}

	full := Full()
	if !strings.Contains(full, Version) {
		t.Errorf("Expected full string to contain version %s, got %s", Version, full)
	}
}

func TestVersionConsistencyWithRootFile(t *testing.T) {
	rootPath := filepath.Join("..", "..", "VERSION")
	content, err := os.ReadFile(rootPath)
	if err != nil {
		t.Skip("Root VERSION file not found, skipping consistency check")
		return
	}

	fileVersion := strings.TrimSpace(string(content))
	fileVersion = strings.TrimPrefix(fileVersion, "v")
	codeVersion := strings.TrimPrefix(Version, "v")

	if fileVersion != codeVersion {
		t.Fatalf("Version mismatch: root VERSION file has %q, but pkg/version/version.go has %q. Please keep them synchronized!", fileVersion, codeVersion)
	}
}

