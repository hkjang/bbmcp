// Package version exposes build-time service version metadata.
package version

// These values are injected at build time via -ldflags.
var (
	Version   = "0.1.0"
	Commit    = "dev"
	BuildDate = "unknown"
	Name      = "bbmcp"
)

// Info is the serialisable version payload shared with the UI.
type Info struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
}

// Current returns the running build's version info.
func Current() Info {
	return Info{Name: Name, Version: Version, Commit: Commit, BuildDate: BuildDate}
}
