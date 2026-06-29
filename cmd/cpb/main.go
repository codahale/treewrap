// Command cpb measures TW128 and AES-128-GCM performance in cycles per byte.
//
// On AMD64, it reads the RDTSC counter directly (reference cycles, no scaling).
// On ARM64, it reads CNTVCT_EL0 and scales to CPU cycles using CNTFRQ_EL0 and
// the CPU frequency (auto-detected or via --freq).
//
// Unless --host=false is given, it also records the host environment (CPU,
// caches, kernel, governor/turbo state, and ISA features) alongside the
// numbers, so a run is a self-contained record of where it was measured.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/codahale/treewrap/tw128"
)

type result struct {
	Alg     string  `json:"alg"`
	Op      string  `json:"op"`
	Size    string  `json:"size"`
	Bytes   int     `json:"bytes"`
	CPB     float64 `json:"cpb"`
	CPBMin  float64 `json:"cpb_min"`
	CPBQ1   float64 `json:"cpb_q1"`
	CPBQ3   float64 `json:"cpb_q3"`
	CPBMax  float64 `json:"cpb_max"`
	GBps    float64 `json:"gbps"`
	GBpsMin float64 `json:"gbps_min"`
	GBpsQ1  float64 `json:"gbps_q1"`
	GBpsQ3  float64 `json:"gbps_q3"`
	GBpsMax float64 `json:"gbps_max"`
}

type sampleStats struct {
	Min    float64
	Q1     float64
	Median float64
	Q3     float64
	Max    float64
}

func main() {
	freq := flag.Float64("freq", 0, "CPU frequency in GHz (auto-detected if omitted)")
	nSamples := flag.Int("samples", 21, "number of measurement samples")
	target := flag.Duration("target", 100*time.Millisecond, "minimum duration per calibration run")
	format := flag.String("format", "table", "output format: table, csv, or json")
	spread := flag.Bool("spread", true, "include min/Q1/median/Q3/max tables in table output")
	host := flag.Bool("host", true, "record host/environment information alongside the results")
	parseFlags()

	if *nSamples < 1 {
		fmt.Fprintln(os.Stderr, "error: --samples must be at least 1")
		os.Exit(2)
	}
	if *target <= 0 {
		fmt.Fprintln(os.Stderr, "error: --target must be positive")
		os.Exit(2)
	}

	// Collect host information before locking to the measurement thread; the
	// probes shell out to lscpu/sysctl and should not run during timing.
	var hi *hostInfo
	if *host {
		h := collectHostInfo()
		hi = &h
	}

	runtime.LockOSThread()

	scale := counterScale(*freq)

	key := make([]byte, tw128.KeySize)
	nonce := make([]byte, tw128.NonceSize)
	aead, err := tw128.New(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tw128:", err)
		os.Exit(1)
	}

	var results []result

	gcmKey := make([]byte, 16)
	gcmNonce := make([]byte, 12)
	gcmBlock, err := aes.NewCipher(gcmKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aes:", err)
		os.Exit(1)
	}
	gcm, err := cipher.NewGCM(gcmBlock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gcm:", err)
		os.Exit(1)
	}

	for _, size := range sizes {
		src := make([]byte, size.N)

		// TW128 seal.
		encDst := make([]byte, 0, size.N+tw128.TagSize)
		encFn := func() {
			encDst = aead.Seal(encDst[:0], nonce, src, nil)
		}
		iters := calibrate(encFn, *target)
		cpb, gbps := measure(encFn, iters, *nSamples, scale, size.N)
		results = append(results, newResult("tw128", "seal", size.Name, size.N, cpb, gbps))

		// TW128 open (decrypt + verify of a pre-sealed ciphertext). Allocate
		// decDst before ct128: the sealed buffer's odd size (size.N +
		// TagSize) would otherwise shift decDst off 2 MiB alignment and cost
		// it transparent-hugepage backing on Linux, slowing the measured
		// streaming stores by up to a third at 16 MiB.
		decDst := make([]byte, 0, size.N)
		ct128 := aead.Seal(nil, nonce, src, nil)
		decFn := func() {
			decDst, _ = aead.Open(decDst[:0], nonce, ct128, nil)
		}
		iters = calibrate(decFn, *target)
		cpb, gbps = measure(decFn, iters, *nSamples, scale, size.N)
		results = append(results, newResult("tw128", "open", size.Name, size.N, cpb, gbps))

		// AES-128-GCM seal.
		gcmDst := make([]byte, 0, size.N+16)
		sealFn := func() {
			gcmDst = gcm.Seal(gcmDst[:0], gcmNonce, src, nil)
		}
		iters = calibrate(sealFn, *target)
		cpb, gbps = measure(sealFn, iters, *nSamples, scale, size.N)
		results = append(results, newResult("aes128gcm", "seal", size.Name, size.N, cpb, gbps))

		// AES-128-GCM open.
		ct := gcm.Seal(nil, gcmNonce, src, nil)
		openDst := make([]byte, 0, size.N)
		openFn := func() {
			openDst, _ = gcm.Open(openDst[:0], gcmNonce, ct, nil)
		}
		iters = calibrate(openFn, *target)
		cpb, gbps = measure(openFn, iters, *nSamples, scale, size.N)
		results = append(results, newResult("aes128gcm", "open", size.Name, size.N, cpb, gbps))
	}

	switch *format {
	case "csv":
		// Keep stdout pure CSV for downstream parsers; the host report, when
		// requested, goes to stderr.
		if hi != nil {
			writeHostReport(os.Stderr, *hi)
		}
		outputCSV(results)
	case "json":
		outputJSON(results, hi)
	default:
		outputTable(results, *freq, *spread, hi)
	}
}

func parseFlags() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	_ = flag.CommandLine.Parse(args)
}

func newResult(alg, op, size string, bytes int, cpb, gbps sampleStats) result {
	return result{
		Alg:     alg,
		Op:      op,
		Size:    size,
		Bytes:   bytes,
		CPB:     cpb.Median,
		CPBMin:  cpb.Min,
		CPBQ1:   cpb.Q1,
		CPBQ3:   cpb.Q3,
		CPBMax:  cpb.Max,
		GBps:    gbps.Median,
		GBpsMin: gbps.Min,
		GBpsQ1:  gbps.Q1,
		GBpsQ3:  gbps.Q3,
		GBpsMax: gbps.Max,
	}
}

// calibrate finds the iteration count that fills at least target duration.
func calibrate(fn func(), target time.Duration) int {
	iters := 1
	for {
		start := time.Now()
		for range iters {
			fn()
		}
		if time.Since(start) >= target {
			return iters
		}
		iters *= 2
	}
}

// measure collects nSamples measurements and returns cycles-per-byte and
// wall-clock throughput statistics in GB/s (1e9 bytes/s). Both metrics are taken
// from the same loop, so their figures describe one interleaved run rather than
// two separately-scheduled measurements.
func measure(fn func(), iters, nSamples int, scale float64, bytes int) (cpb, gbps sampleStats) {
	fn() // warm up

	cpbs := make([]float64, nSamples)
	gbpss := make([]float64, nSamples)
	for i := range nSamples {
		wall := time.Now()
		start := readCounter()
		for range iters {
			fn()
		}
		end := readCounter()
		elapsed := time.Since(wall)

		ticksPerOp := float64(end-start) / float64(iters)
		cpbs[i] = ticksPerOp * scale / float64(bytes)

		secsPerOp := elapsed.Seconds() / float64(iters)
		gbpss[i] = float64(bytes) / secsPerOp / 1e9
	}

	slices.Sort(cpbs)
	slices.Sort(gbpss)
	return statsFromSorted(cpbs), statsFromSorted(gbpss)
}

func statsFromSorted(xs []float64) sampleStats {
	if len(xs) == 0 {
		return sampleStats{}
	}
	return sampleStats{
		Min:    xs[0],
		Q1:     percentileSorted(xs, 0.25),
		Median: xs[len(xs)/2],
		Q3:     percentileSorted(xs, 0.75),
		Max:    xs[len(xs)-1],
	}
}

func percentileSorted(xs []float64, p float64) float64 {
	if len(xs) == 1 {
		return xs[0]
	}
	pos := p * float64(len(xs)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return xs[lo]
	}
	frac := pos - float64(lo)
	return xs[lo]*(1-frac) + xs[hi]*frac
}

func outputTable(results []result, freqGHz float64, spread bool, host *hostInfo) {
	if host != nil {
		writeHostReport(os.Stdout, *host)
		fmt.Println()
	}

	fmt.Printf("cycles/byte (%s/%s", runtime.GOOS, runtime.GOARCH)
	if freqGHz > 0 {
		fmt.Printf(", %.2f GHz", freqGHz)
	}
	fmt.Println(")")
	fmt.Println()
	printGrid(results, func(r result) float64 { return r.CPB })

	fmt.Println()
	fmt.Printf("throughput (GB/s, 1e9 bytes/s, wall-clock) (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()
	printGrid(results, func(r result) float64 { return r.GBps })

	if spread {
		fmt.Println()
		fmt.Printf("cycles/byte spread (min, q1, median, q3, max) (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
		fmt.Println()
		printSpread(results, func(r result) sampleStats {
			return sampleStats{Min: r.CPBMin, Q1: r.CPBQ1, Median: r.CPB, Q3: r.CPBQ3, Max: r.CPBMax}
		})

		fmt.Println()
		fmt.Printf("throughput spread (GB/s, min, q1, median, q3, max) (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
		fmt.Println()
		printSpread(results, func(r result) sampleStats {
			return sampleStats{Min: r.GBpsMin, Q1: r.GBpsQ1, Median: r.GBps, Q3: r.GBpsQ3, Max: r.GBpsMax}
		})
	}
}

// printGrid renders one metric as an algorithm-by-length grid. The value
// selector picks which field of each result to show, so the same layout serves
// both the cycles-per-byte and throughput tables. Results are ordered
// size-major with the same alg/op rows repeated per size, so cells are indexed
// positionally.
func printGrid(results []result, value func(result) float64) {
	nRows := len(results) / len(sizes)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	_, _ = fmt.Fprint(w, "\t")
	for _, s := range sizes {
		_, _ = fmt.Fprintf(w, "%s\t", s.Name)
	}
	_, _ = fmt.Fprintln(w)

	for i := range nRows {
		_, _ = fmt.Fprintf(w, "%s %s\t", results[i].Alg, results[i].Op)
		for j := range sizes {
			v := value(results[j*nRows+i])
			if v >= 100 {
				_, _ = fmt.Fprintf(w, "%.0f\t", v)
			} else {
				_, _ = fmt.Fprintf(w, "%.2f\t", v)
			}
		}
		_, _ = fmt.Fprintln(w)
	}
	_ = w.Flush()
}

func printSpread(results []result, stats func(result) sampleStats) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	_, _ = fmt.Fprintln(w, "alg\top\tsize\tmin\tq1\tmedian\tq3\tmax\t")
	for _, r := range results {
		s := stats(r)
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			r.Alg,
			r.Op,
			r.Size,
			formatValue(s.Min),
			formatValue(s.Q1),
			formatValue(s.Median),
			formatValue(s.Q3),
			formatValue(s.Max),
		)
	}
	_ = w.Flush()
}

func formatValue(v float64) string {
	if v >= 100 {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.2f", v)
}

func outputCSV(results []result) {
	w := csv.NewWriter(os.Stdout)
	_ = w.Write([]string{
		"alg", "operation", "size", "bytes",
		"cpb", "cpb_min", "cpb_q1", "cpb_q3", "cpb_max",
		"gbps", "gbps_min", "gbps_q1", "gbps_q3", "gbps_max",
	})
	for _, r := range results {
		_ = w.Write([]string{
			r.Alg,
			r.Op,
			r.Size,
			fmt.Sprint(r.Bytes),
			formatCPB(r.CPB),
			formatCPB(r.CPBMin),
			formatCPB(r.CPBQ1),
			formatCPB(r.CPBQ3),
			formatCPB(r.CPBMax),
			formatGBps(r.GBps),
			formatGBps(r.GBpsMin),
			formatGBps(r.GBpsQ1),
			formatGBps(r.GBpsQ3),
			formatGBps(r.GBpsMax),
		})
	}
	w.Flush()
}

func formatCPB(v float64) string {
	return fmt.Sprintf("%.2f", v)
}

func formatGBps(v float64) string {
	return fmt.Sprintf("%.4f", v)
}

// jsonReport bundles the host environment with the measurements so the JSON
// output is a single self-contained record.
type jsonReport struct {
	Host    *hostInfo `json:"host,omitempty"`
	Results []result  `json:"results"`
}

func outputJSON(results []result, host *hostInfo) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(jsonReport{Host: host, Results: results})
}

type size struct {
	Name string
	N    int
}

var sizes = []size{
	{"1B", 1},
	{"64B", 64},
	{"8KiB", 8 * 1024},
	{"32KiB", 32 * 1024},
	{"64KiB", 64 * 1024},
	{"1MiB", 1024 * 1024},
	{"16MiB", 16 * 1024 * 1024},
}
