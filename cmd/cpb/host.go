package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// hostInfo records the benchmarking environment so that a cpb run is a
// self-contained record of the machine it was measured on. The free-form
// Sections carry the per-platform host details collected in
// paper/sections/09-performance.tex (lscpu, microcode, governor, and SMT on
// Linux; chip, topology, caches, and ISA features on macOS).
type hostInfo struct {
	OS        string        `json:"os"`
	Arch      string        `json:"arch"`
	GoVersion string        `json:"go_version"`
	NumCPU    int           `json:"num_cpu"`
	Hostname  string        `json:"hostname,omitempty"`
	Sections  []hostSection `json:"sections,omitempty"`
}

// hostSection is a single named block of host detail, such as the output of
// lscpu or a group of sysctl values.
type hostSection struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// collectHostInfo gathers the runtime identity of the machine and the
// platform-specific host sections supplied by hostSections.
func collectHostInfo() hostInfo {
	h := hostInfo{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		NumCPU:    runtime.NumCPU(),
		Sections:  hostSections(),
	}
	if name, err := os.Hostname(); err == nil {
		h.Hostname = name
	}
	return h
}

// writeHostReport renders the host information as the same "=== Title ===" block
// layout used for the recorded environments in 09-performance.tex, so a cpb run
// can be pasted into the paper alongside its numbers.
func writeHostReport(w io.Writer, h hostInfo) {
	summary := fmt.Sprintf("%s/%s, %s, %d CPU", h.OS, h.Arch, h.GoVersion, h.NumCPU)
	if h.Hostname != "" {
		summary += ", " + h.Hostname
	}
	_, _ = fmt.Fprintf(w, "=== host (%s) ===\n", summary)
	for _, s := range h.Sections {
		_, _ = fmt.Fprintf(w, "\n=== %s ===\n%s\n", s.Title, s.Body)
	}
}

// sectionList accumulates host sections, dropping any whose body could not be
// collected so that an absent tool or sysfs file is silently skipped.
type sectionList []hostSection

func (s *sectionList) add(title, body string) {
	if strings.TrimSpace(body) != "" {
		*s = append(*s, hostSection{Title: title, Body: body})
	}
}

// runCmd runs a command and returns its trimmed standard output, or "" on any
// error (including the command not existing).
func runCmd(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(out), "\n")
}

// readFileTrim reads a file and returns its trimmed contents, or "" on error.
func readFileTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
