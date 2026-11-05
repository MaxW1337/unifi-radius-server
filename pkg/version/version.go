package version

import (
	"fmt"
	"runtime"
	"strings"
)

// Version is the single source of truth for the application version in Go.
// When preparing a new release, bump this constant (and the root VERSION file).
const Version = "1.0.5"

// Build variables injected at compile time via -ldflags.
var (
	GitCommit = "dev"
	BuildDate = "dev"
)

// Info holds complete version and runtime metadata.
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Compiler  string `json:"compiler"`
	Platform  string `json:"platform"`
}

// Get returns the structured version info.
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Compiler:  runtime.Compiler,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// String returns the normalized version string (without leading 'v').
func String() string {
	return strings.TrimPrefix(Version, "v")
}

// Full returns a formatted version string with commit, build date and platform.
func Full() string {
	return fmt.Sprintf("unifi-radius-server %s (commit: %s, built: %s, os/arch: %s/%s)",
		Version, GitCommit, BuildDate, runtime.GOOS, runtime.GOARCH)
}

