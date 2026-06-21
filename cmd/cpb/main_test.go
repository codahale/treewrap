package main

import "testing"

func TestStatsFromSortedOdd(t *testing.T) {
	got := statsFromSorted([]float64{1, 2, 3, 4, 5})
	want := sampleStats{Min: 1, Q1: 2, Median: 3, Q3: 4, Max: 5}
	if got != want {
		t.Fatalf("statsFromSorted odd = %+v, want %+v", got, want)
	}
}

func TestStatsFromSortedEvenKeepsUpperMedian(t *testing.T) {
	got := statsFromSorted([]float64{1, 2, 3, 4})
	want := sampleStats{Min: 1, Q1: 1.75, Median: 3, Q3: 3.25, Max: 4}
	if got != want {
		t.Fatalf("statsFromSorted even = %+v, want %+v", got, want)
	}
}
