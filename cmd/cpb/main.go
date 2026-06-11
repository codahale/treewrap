// Command cpb measures TW128 and AES-128-GCM performance in cycles per byte.
//
// On AMD64, it reads the RDTSC counter directly (reference cycles, no scaling).
// On ARM64, it reads CNTVCT_EL0 and scales to CPU cycles using CNTFRQ_EL0 and
// the CPU frequency (auto-detected or via --freq).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/codahale/treewrap/tw128"
)

type result struct {
	Alg   string  `json:"alg"`
	Op    string  `json:"op"`
	Size  string  `json:"size"`
	Bytes int     `json:"bytes"`
	CPB   float64 `json:"cpb"`
	GBps  float64 `json:"gbps"`
}

func main() {
	freq := flag.Float64("freq", 0, "CPU frequency in GHz (auto-detected if omitted)")
	nSamples := flag.Int("samples", 21, "number of measurement samples")
	target := flag.Duration("target", 100*time.Millisecond, "minimum duration per calibration run")
	format := flag.String("format", "table", "output format: table, csv, or json")
	flag.Parse()

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

	for _, size := range sizes {
		src := make([]byte, size.N)

		// TW128 seal.
		encDst := make([]byte, 0, size.N+tw128.TagSize)
		encFn := func() {
			encDst = aead.Seal(encDst[:0], nonce, src, nil)
		}
		iters := calibrate(encFn, *target)
		cpb, gbps := measure(encFn, iters, *nSamples, scale, size.N)
		results = append(results, result{
			Alg: "tw128", Op: "seal", Size: size.Name, Bytes: size.N,
			CPB: cpb, GBps: gbps,
		})

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
		results = append(results, result{
			Alg: "tw128", Op: "open", Size: size.Name, Bytes: size.N,
			CPB: cpb, GBps: gbps,
		})

		// AES-128-GCM seal (key schedule included in measurement).
		gcmDst := make([]byte, 0, size.N+16)
		sealFn := func() {
			block, _ := aes.NewCipher(gcmKey)
			gcm, _ := cipher.NewGCM(block)
			gcmDst = gcm.Seal(gcmDst[:0], gcmNonce, src, nil)
		}
		iters = calibrate(sealFn, *target)
		cpb, gbps = measure(sealFn, iters, *nSamples, scale, size.N)
		results = append(results, result{
			Alg: "aes128gcm", Op: "seal", Size: size.Name, Bytes: size.N,
			CPB: cpb, GBps: gbps,
		})

		// AES-128-GCM open (key schedule included in measurement).
		block, _ := aes.NewCipher(gcmKey)
		gcm, _ := cipher.NewGCM(block)
		ct := gcm.Seal(nil, gcmNonce, src, nil)
		openDst := make([]byte, 0, size.N)
		openFn := func() {
			block, _ := aes.NewCipher(gcmKey)
			gcm, _ := cipher.NewGCM(block)
			openDst, _ = gcm.Open(openDst[:0], gcmNonce, ct, nil)
		}
		iters = calibrate(openFn, *target)
		cpb, gbps = measure(openFn, iters, *nSamples, scale, size.N)
		results = append(results, result{
			Alg: "aes128gcm", Op: "open", Size: size.Name, Bytes: size.N,
			CPB: cpb, GBps: gbps,
		})
	}

	switch *format {
	case "csv":
		outputCSV(results)
	case "json":
		outputJSON(results)
	default:
		outputTable(results, *freq)
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

// measure collects nSamples measurements and returns the median cycles per byte
// and the median wall-clock throughput in GB/s (1e9 bytes/s). Both are taken from
// the same loop, so the cycles-per-byte and throughput figures describe one
// interleaved run rather than two separately-scheduled measurements.
func measure(fn func(), iters, nSamples int, scale float64, bytes int) (cpb, gbps float64) {
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
	return cpbs[len(cpbs)/2], gbpss[len(gbpss)/2]
}

func outputTable(results []result, freqGHz float64) {
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
}

// printGrid renders one metric as an algorithm-by-length grid. The value
// selector picks which field of each result to show, so the same layout serves
// both the cycles-per-byte and throughput tables.
func printGrid(results []result, value func(result) float64) {
	// Collect ordered unique sizes and row keys.
	var sizes []string
	sizeSeen := make(map[string]bool)
	var rows []string
	rowSeen := make(map[string]bool)
	for _, r := range results {
		if !sizeSeen[r.Size] {
			sizes = append(sizes, r.Size)
			sizeSeen[r.Size] = true
		}
		key := r.Alg + " " + r.Op
		if !rowSeen[key] {
			rows = append(rows, key)
			rowSeen[key] = true
		}
	}

	vals := make(map[string]float64)
	for _, r := range results {
		vals[r.Alg+" "+r.Op+"/"+r.Size] = value(r)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprint(w, "\t")
	for _, s := range sizes {
		fmt.Fprintf(w, "%s\t", s)
	}
	fmt.Fprintln(w)

	for _, row := range rows {
		fmt.Fprintf(w, "%s\t", row)
		for _, s := range sizes {
			v := vals[row+"/"+s]
			if v >= 100 {
				fmt.Fprintf(w, "%.0f\t", v)
			} else {
				fmt.Fprintf(w, "%.2f\t", v)
			}
		}
		fmt.Fprintln(w)
	}
	w.Flush()
}

func outputCSV(results []result) {
	w := csv.NewWriter(os.Stdout)
	_ = w.Write([]string{"alg", "operation", "size", "bytes", "cpb", "gbps"})
	for _, r := range results {
		_ = w.Write([]string{r.Alg, r.Op, r.Size, fmt.Sprint(r.Bytes), fmt.Sprintf("%.2f", r.CPB), fmt.Sprintf("%.4f", r.GBps)})
	}
	w.Flush()
}

func outputJSON(results []result) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
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
