// Package errchain provides convenient types to work with nested errors
// that go through a series of deeply nested calls.
package errchain

import "fmt"

// ChainedError is a type of error that only displays the outermost error message
// and the innermost error message by default when printed, sparing the
// user from having to wade through potentially long chains of errors to get to the root cause.
//
// Use WithFormat to switch between Concise (default) and Verbose display modes.
type ChainedError interface {
	error
	Unwrap() error
	WithFormat(Format) ChainedError
}

// Format specifies how error chains should be displayed when formatted as strings.
type Format int

const (
	// Concise format displays only the outermost and innermost errors in a chain,
	// omitting intermediate errors. This is the default format.
	// Example: "outer error: root cause"
	Concise Format = iota

	// Verbose format displays the complete error chain with all intermediate errors.
	// Example: "outer error: middle error: root cause"
	Verbose
)

// Default is the default format used when creating new ChainedError instances.
const Default = Concise

type chainedError struct {
	parent    error
	child     error
	innermost error
	format    Format
}

// Wrap creates a new error by wrapping child with parent.
//
// Nil handling (IMPORTANT):
//   - If both are nil: returns nil
//   - If parent is nil: returns child as-is
//   - If child is nil: returns nil (prevents masking success as failure)
//
// For non-nil inputs, returns a ChainedError that displays errors according to the
// Concise format by default (showing only outermost and innermost errors).
//
// To use Verbose format, use the package-level WithFormat function (recommended):
//
//	err := errchain.Wrap(parent, child)
//	verboseErr := errchain.WithFormat(err, errchain.Verbose)
//	fmt.Println(verboseErr) // Shows full chain
//
// Circular reference protection: Error chains deeper than 1000 levels will
// stop traversal to prevent infinite loops.
//
// Concurrency: Safe for concurrent use. All errors are immutable.
//
// Note: This function is defensive and handles nil inputs gracefully, but callers
// should validate errors before wrapping when possible to maintain clear error chains.
func Wrap(parent, child error) error {
	// Handle nil cases
	if parent == nil && child == nil {
		return nil
	}
	if parent == nil {
		return child
	}
	if child == nil {
		// CRITICAL: Return nil instead of parent to prevent masking success as failure
		return nil
	}

	// Get the innermost error from the child by traversing the entire unwrap chain.
	// We use the standard Unwrap() interface (not ChainedError) to traverse through
	// ALL error types including wrapper types like ParseError, verifyError, etc.
	//
	// The innermost error is the last error in the chain before:
	// 1. An error that doesn't implement Unwrap(), OR
	// 2. An error whose Unwrap() returns nil
	//
	// Use depth limit to prevent infinite loops from circular references.
	//
	// CYCLE DETECTION STRATEGY:
	// We use a two-pronged approach to handle circular error references:
	//
	// 1. Immediate self-reference detection: `next == innermost` catches the case
	//    where an error's Unwrap() returns itself directly.
	//
	// 2. maxDepth limit: This is the PRIMARY defense against longer cycles
	//    (e.g., A->B->A or A->B->C->A). Full cycle detection with a seen map
	//    was considered but rejected due to allocation overhead - tracking
	//    visited errors would require a map allocation for every Wrap() call,
	//    even though circular references are extremely rare in practice.
	//
	// This is a conscious design decision: we accept that chains with cycles
	// longer than immediate self-reference will traverse up to maxDepth times
	// before stopping, rather than incur allocation overhead on every call.
	//
	// maxDepth limits traversal to prevent DoS from circular references.
	// 1000 is chosen to be far beyond any legitimate error chain (typical depth < 20)
	// while still completing in microseconds on modern hardware.
	innermost := child
	depth := 0
	const maxDepth = 1000

	for {
		// Use standard Unwrap() interface to traverse ALL error types
		// This is the key fix: we check for interface{ Unwrap() error }
		// instead of ChainedError, so we can traverse through wrapper types
		// like ParseError, verifyError, etc.
		unwrapper, ok := innermost.(interface{ Unwrap() error })
		if !ok {
			// This error doesn't implement Unwrap() - it's the innermost
			break
		}

		next := unwrapper.Unwrap()
		if next == nil || next == innermost {
			// Chain ends here - current error is the innermost
			// Check for next == innermost to prevent immediate circular references
			// (e.g., an error whose Unwrap() returns itself)
			break
		}

		// Increment depth AFTER checking for nil/self-reference
		// This ensures we don't break early at depth 1001 when the chain legitimately ends
		depth++
		if depth > maxDepth {
			// Possible circular reference - stop traversal to prevent DoS
			break
		}

		innermost = next
	}

	return &chainedError{
		parent:    parent,
		child:     child,
		innermost: innermost,
		format:    Default,
	}
}

// WithFormat returns an error with the specified format if err is a ChainedError,
// otherwise returns err unchanged.
//
// This is the recommended way to apply format to errors, as it handles type
// assertion internally and works with any error type.
//
// Examples:
//
//	// Apply verbose format for debugging
//	log.Debug(errchain.WithFormat(err, errchain.Verbose))
//
//	// Use concise format for user display
//	fmt.Println(errchain.WithFormat(err, errchain.Concise))
//
//	// Works with non-ChainedError (passes through unchanged)
//	regularErr := errors.New("test")
//	sameErr := errchain.WithFormat(regularErr, errchain.Verbose)
//
// Format semantics: The format applies only to the current error level's
// display, not recursively to the entire chain.
//
// Concurrency: Safe for concurrent use. Creates a new error instance if
// err is a ChainedError.
func WithFormat(err error, f Format) error {
	if ce, ok := err.(ChainedError); ok {
		return ce.WithFormat(f)
	}
	return err
}

func (e *chainedError) Error() string {
	if e.format == Verbose {
		return e.verboseError()
	}
	return e.conciseError()
}

func (e *chainedError) Unwrap() error {
	return e.child
}

// WithFormat returns a new ChainedError with the specified format.
// The original error is not modified (immutable pattern).
//
// Note: Users should prefer the package-level WithFormat() function for better
// ergonomics, as it handles type assertion internally.
//
// Format semantics: The format applies only to this error level's display,
// not recursively to the entire chain.
//
// Performance: Allocates a new chainedError struct (4 fields). Cache the result
// if calling repeatedly in performance-sensitive code.
//
// Example:
//
//	err := errchain.Wrap(outer, inner)
//	if ce, ok := err.(errchain.ChainedError); ok {
//	    verboseErr := ce.WithFormat(errchain.Verbose)
//	    fmt.Println(verboseErr) // Shows full chain
//	    fmt.Println(ce)         // Original still shows concise format
//	}
func (e *chainedError) WithFormat(f Format) ChainedError {
	return &chainedError{
		parent:    e.parent,
		child:     e.child,
		innermost: e.innermost,
		format:    f,
	}
}

func (e *chainedError) verboseError() string {
	return fmt.Sprintf("%s: %s", e.parent, e.child)
}

func (e *chainedError) conciseError() string {
	return fmt.Sprintf("%s: %s", e.parent, e.innermost)
}

// Format implements fmt.Formatter to support %+v for verbose debugging.
// %s, %v: Use error's format setting (default: concise)
// %+v:    Always show full chain (for debugging)
func (e *chainedError) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			// %+v: Always show verbose output for debugging
			fmt.Fprint(s, e.verboseError())
			return
		}
		fallthrough
	case 's':
		fmt.Fprint(s, e.Error())
	default:
		fmt.Fprint(s, e.Error())
	}
}
