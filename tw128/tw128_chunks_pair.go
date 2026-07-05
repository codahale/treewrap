package tw128

func initPairStateFromDuplexes(s *state8, d0, d1 *duplex) {
	for lane := range lanes {
		s.a[lane][0] = d0.a[lane]
		s.a[lane][1] = d1.a[lane]
	}
}
