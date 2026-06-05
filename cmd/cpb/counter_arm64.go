//go:build arm64 && !purego

package main

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
)

//go:noescape
func cntvct() uint64

//go:noescape
func cntfrq() uint64

//go:noescape
func calibOps(iters uint64) uint64

func readCounter() uint64 { return cntvct() }

func counterScale(freqGHz float64) float64 {
	cf := float64(cntfrq())
	if cf == 0 {
		fmt.Fprintln(os.Stderr, "error: CNTFRQ_EL0 returned 0")
		os.Exit(1)
	}

	cpuHz := freqGHz * 1e9
	if cpuHz == 0 {
		cpuHz = detectCPUFreq()
	}
	if cpuHz == 0 {
		fmt.Fprintln(os.Stderr, "error: could not detect CPU frequency; specify --freq in GHz (e.g. --freq=3.5)")
		os.Exit(1)
	}

	return cpuHz / cf
}

func detectCPUFreq() float64 {
	// Linux exposes the spec max cheaply via sysfs; prefer it when present.
	if runtime.GOOS == "linux" {
		if hz := detectLinux(); hz > 0 {
			return hz
		}
	}
	// Apple Silicon has no public API for the CPU frequency (hw.cpufrequency*
	// exist only on Intel Macs), and sysfs may be absent elsewhere. Fall back
	// to measuring the peak frequency directly.
	return measureCPUFreq()
}

// measureCPUFreq estimates the peak CPU frequency in Hz by timing a dependent
// integer-ADD chain against CNTVCT. calibOps runs 64*iters ADDs at 1 cycle/op,
// so freq = ops / elapsed. Taking the minimum elapsed time over several runs
// selects the top DVFS P-state, which is the right reference for cycles/byte.
func measureCPUFreq() float64 {
	const unroll = 64
	const iters = 40_000_000
	const ops = float64(unroll) * float64(iters)

	cf := float64(cntfrq())
	if cf == 0 {
		return 0
	}
	calibOps(iters / 4) // warm up: ramp the core to its top P-state

	best := math.Inf(1)
	for range 8 {
		t0 := cntvct()
		_ = calibOps(iters)
		t1 := cntvct()
		if s := float64(t1-t0) / cf; s < best {
			best = s
		}
	}
	return ops / best
}

func detectLinux() float64 {
	// cpuinfo_max_freq reports kHz on Linux.
	data, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
	if err == nil {
		if khz, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil && khz > 0 {
			return khz * 1e3
		}
	}
	return 0
}
