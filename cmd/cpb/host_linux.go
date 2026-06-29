//go:build linux

package main

import (
	"os"
	"strings"
)

// hostSections collects the Linux host details recorded for the amd64
// benchmarking machine in 07-performance.tex: the lscpu summary, the per-core
// microcode and model from /proc/cpuinfo, the frequency governor and scaling
// driver, the turbo and SMT state, and the kernel release. Any probe whose tool
// or sysfs path is missing is skipped.
func hostSections() []hostSection {
	var s sectionList
	s.add("lscpu", runCmd("lscpu"))
	s.add("microcode/model (cpuinfo, core 0)", firstCPUInfoBlock())
	s.add("governor", readFileTrim("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"))
	s.add("scaling driver", readFileTrim("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver"))
	s.add("turbo (intel_pstate: 1=disabled)", readFileTrim("/sys/devices/system/cpu/intel_pstate/no_turbo"))
	s.add("turbo (acpi-cpufreq/amd boost: 1=enabled)", readFileTrim("/sys/devices/system/cpu/cpufreq/boost"))
	s.add("SMT", readFileTrim("/sys/devices/system/cpu/smt/active"))
	s.add("kernel", runCmd("uname", "-srmo"))
	return s
}

// firstCPUInfoBlock returns the first processor block of /proc/cpuinfo, which
// carries the per-core microcode revision and model name that lscpu omits.
func firstCPUInfoBlock() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	block, _, _ := strings.Cut(string(data), "\n\n")
	return strings.TrimSpace(block)
}

// readFileTrim reads a file and returns its trimmed contents, or "" on error.
func readFileTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
