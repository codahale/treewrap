//go:build darwin

package main

// hostSections collects the macOS host details recorded for the arm64
// benchmarking machine in 09-performance.tex: the chip and model identifiers,
// the OS and kernel versions, the performance/efficiency core topology, the
// cache hierarchy, and the optional ISA features (including FEAT_SHA3). The
// sysctl groups print one "name: value" line per key, matching the recorded
// layout.
func hostSections() []hostSection {
	var s sectionList
	s.add("chip", runCmd("sysctl", "-n", "machdep.cpu.brand_string"))
	s.add("model", runCmd("sysctl", "-n", "hw.model"))
	s.add("os", runCmd("sw_vers"))
	s.add("kernel", runCmd("uname", "-srm"))
	s.add("core topology (perflevel0=P-cores, perflevel1=E-cores)", runCmd("sysctl",
		"hw.ncpu", "hw.physicalcpu", "hw.logicalcpu",
		"hw.perflevel0.physicalcpu", "hw.perflevel0.logicalcpu",
		"hw.perflevel1.physicalcpu", "hw.perflevel1.logicalcpu"))
	s.add("caches", runCmd("sysctl",
		"hw.l1icachesize", "hw.l1dcachesize", "hw.l2cachesize",
		"hw.perflevel0.l2cachesize", "hw.perflevel1.l2cachesize",
		"hw.pagesize", "hw.memsize"))
	s.add("ISA optional features", runCmd("sysctl", "hw.optional"))
	return s
}
