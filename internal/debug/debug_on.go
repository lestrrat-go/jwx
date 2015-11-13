//+build debug

package debug

import "log"

func Printf(f string, args ...interface{}) {
	log.Printf(f, args...)
}
