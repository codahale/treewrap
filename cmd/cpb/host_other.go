//go:build !linux && !darwin

package main

// hostSections returns no platform-specific detail on systems without a host
// probe; collectHostInfo still records the OS, architecture, Go version, CPU
// count, and hostname.
func hostSections() []hostSection { return nil }
