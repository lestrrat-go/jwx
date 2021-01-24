package bench_test

import "testing"

// Case is a single benchmark case
type Case struct {
	Name    string
	Pretest func(*testing.B) error
	Test    func(*testing.B) error
}

func (c *Case) Run(b *testing.B) {
	b.Helper()
	b.Run(c.Name, func(b *testing.B) {
		b.Helper()
		for i := 0; i < b.N; i++ {
			if pretest := c.Pretest; pretest != nil {
				if err := pretest(b); err != nil {
					b.Fatal(err)
				}
			}
			if err := c.Test(b); err != nil {
				b.Fatal(err)
			}
		}
	})
}
