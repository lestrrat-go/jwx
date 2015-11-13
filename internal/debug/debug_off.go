//+build !debug

package debug

// Printf is no op unless you compile with the `debug` tag
func Printf(f string, args ...interface{}) {}
