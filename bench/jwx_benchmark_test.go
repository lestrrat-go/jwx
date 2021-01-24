package bench_test

import "testing"

// Case is a single benchmark case
type Case struct {
	Name      string
	Pretest   func(*testing.B) error
	SkipShort bool // Skip benchmark on short mode
	Test      func(*testing.B) error
}

func (c *Case) Run(b *testing.B) {
	b.Helper()
	b.Run(c.Name, func(b *testing.B) {
		if c.SkipShort {
			b.SkipNow()
		}

		b.Helper()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			if pretest := c.Pretest; pretest != nil {
				if err := pretest(b); err != nil {
					b.Fatal(err)
				}
			}
			b.StartTimer()
			if err := c.Test(b); err != nil {
				b.Fatal(err)
			}
		}
	})
}
