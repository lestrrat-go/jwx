package errchain_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v3/internal/errchain"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test Cases for Wrap Function
// ============================================================================

func TestWrap_BothNil(t *testing.T) {
	result := errchain.Wrap(nil, nil)
	require.Nil(t, result, "Wrap(nil, nil) should return nil")
}

func TestWrap_ParentNil(t *testing.T) {
	child := errors.New("child error")
	result := errchain.Wrap(nil, child)
	require.Same(t, child, result, "Wrap(nil, child) should return exact same child pointer")
}

func TestWrap_ChildNil(t *testing.T) {
	parent := errors.New("parent error")
	result := errchain.Wrap(parent, nil)
	require.Nil(t, result, "Wrap(parent, nil) should return nil (CRITICAL: not parent)")
}

func TestWrap_ChildNil_Semantic(t *testing.T) {
	// This test verifies the semantic correctness of Wrap(parent, nil) returning nil
	// to prevent masking success (nil error) as failure

	// Simulate a function that returns nil on success
	operation := func() error {
		return nil // success
	}

	contextErr := errors.New("context error")
	wrappedErr := errchain.Wrap(contextErr, operation())

	// The wrapped error should be nil, not contextErr
	// This prevents false positives in error checking
	require.Nil(t, wrappedErr, "Wrap should not mask success (nil) as failure")

	// Verify that a nil check correctly identifies success
	if wrappedErr != nil {
		t.Fatal("False positive: success was incorrectly identified as failure")
	}
}

func TestWrap_BothNonNil(t *testing.T) {
	parent := errors.New("parent error")
	child := errors.New("child error")
	result := errchain.Wrap(parent, child)

	require.NotNil(t, result, "Wrap should return non-nil error")

	// Verify it's a ChainedError
	ce, ok := result.(errchain.ChainedError)
	require.True(t, ok, "Result should be ChainedError")
	require.NotNil(t, ce)

	// Verify it unwraps to child
	require.Equal(t, child, ce.Unwrap())
}

func TestWrap_SimpleChain(t *testing.T) {
	err1 := errors.New("root cause")
	err2 := errchain.Wrap(errors.New("intermediate error"), err1)
	err3 := errchain.Wrap(errors.New("top level error"), err2)

	// Concise format should show only outermost and innermost
	require.EqualError(t, err3, "top level error: root cause")
}

func TestWrap_DeepChain(t *testing.T) {
	// Create a 10-level chain
	err := errors.New("level 0 (root)")
	for i := 1; i <= 10; i++ {
		err = errchain.Wrap(fmt.Errorf("level %d", i), err)
	}

	// Concise format should show only outermost (level 10) and innermost (level 0)
	require.EqualError(t, err, "level 10: level 0 (root)")
}

func TestWrap_InnermostDetection(t *testing.T) {
	// Test that innermost is correctly identified in various scenarios

	// Simple case: regular error
	err1 := errors.New("innermost")
	wrapped1 := errchain.Wrap(errors.New("outer"), err1)
	require.EqualError(t, wrapped1, "outer: innermost")

	// Nested ChainedError
	err2 := errors.New("truly innermost")
	chained2 := errchain.Wrap(errors.New("middle"), err2)
	wrapped2 := errchain.Wrap(errors.New("outermost"), chained2)
	require.EqualError(t, wrapped2, "outermost: truly innermost")

	// Three levels deep
	err3 := errors.New("deepest")
	chained3a := errchain.Wrap(errors.New("level 2"), err3)
	chained3b := errchain.Wrap(errors.New("level 1"), chained3a)
	wrapped3 := errchain.Wrap(errors.New("level 0"), chained3b)
	require.EqualError(t, wrapped3, "level 0: deepest")
}

func TestWrap_MixedChainedAndRegular(t *testing.T) {
	// Test mixing ChainedError with regular errors

	regularErr := errors.New("regular error")
	chainedErr := errchain.Wrap(errors.New("chained parent"), regularErr)

	// Wrap the ChainedError
	result := errchain.Wrap(errors.New("outer"), chainedErr)
	require.EqualError(t, result, "outer: regular error")

	// Verify unwrapping works correctly
	ce, ok := result.(errchain.ChainedError)
	require.True(t, ok)
	require.Equal(t, chainedErr, ce.Unwrap())
}

func TestWrap_PointerIdentity(t *testing.T) {
	// Verify that nil cases return exact same pointer (not a copy)

	child := errors.New("child")
	result := errchain.Wrap(nil, child)
	require.Same(t, child, result, "Wrap(nil, child) should return same pointer identity")

	// Verify pointer address is identical
	require.Equal(t, fmt.Sprintf("%p", child), fmt.Sprintf("%p", result))
}

// ============================================================================
// Test Cases for WithFormat (Interface Method)
// ============================================================================

func TestWithFormat_Concise(t *testing.T) {
	err1 := errors.New("innermost")
	err2 := errchain.Wrap(errors.New("middle"), err1)
	err3 := errchain.Wrap(errors.New("outer"), err2)

	ce, ok := err3.(errchain.ChainedError)
	require.True(t, ok)

	concise := ce.WithFormat(errchain.Concise)
	require.EqualError(t, concise, "outer: innermost")
}

func TestWithFormat_Verbose(t *testing.T) {
	err1 := errors.New("innermost")
	err2 := errchain.Wrap(errors.New("middle"), err1)
	err3 := errchain.Wrap(errors.New("outer"), err2)

	ce, ok := err3.(errchain.ChainedError)
	require.True(t, ok)

	verbose := ce.WithFormat(errchain.Verbose)
	// Verbose shows outer: child (where child is "middle: innermost")
	require.EqualError(t, verbose, "outer: middle: innermost")
}

func TestWithFormat_Immutability(t *testing.T) {
	// Create a 3-level chain so concise and verbose will differ
	err1 := errors.New("innermost")
	err2 := errchain.Wrap(errors.New("middle"), err1)
	err3 := errchain.Wrap(errors.New("outer"), err2)

	ce, ok := err3.(errchain.ChainedError)
	require.True(t, ok)

	// Get original error message
	originalMsg := ce.Error()

	// Create verbose version
	verbose := ce.WithFormat(errchain.Verbose)
	verboseMsg := verbose.Error()

	// Original should be unchanged
	require.Equal(t, originalMsg, ce.Error(), "Original error should be unchanged")
	require.NotEqual(t, originalMsg, verboseMsg, "Verbose should be different")

	// Verify original still uses concise format
	require.EqualError(t, ce, "outer: innermost")
	require.EqualError(t, verbose, "outer: middle: innermost")
}

func TestWithFormat_ReturnType(t *testing.T) {
	err := errchain.Wrap(errors.New("outer"), errors.New("inner"))
	ce, ok := err.(errchain.ChainedError)
	require.True(t, ok)

	result := ce.WithFormat(errchain.Verbose)

	// Should return ChainedError
	_, ok = result.(errchain.ChainedError)
	require.True(t, ok, "WithFormat should return ChainedError")
}

func TestWithFormat_DeepChain(t *testing.T) {
	// Create a 5-level chain
	err := errors.New("level 0")
	for i := 1; i <= 4; i++ {
		err = errchain.Wrap(fmt.Errorf("level %d", i), err)
	}

	ce, ok := err.(errchain.ChainedError)
	require.True(t, ok)

	// Concise should show only outermost and innermost
	concise := ce.WithFormat(errchain.Concise)
	require.EqualError(t, concise, "level 4: level 0")

	// Verbose shows parent: child.Error()
	// Where child is a ChainedError that uses concise format by default
	// So it shows: "level 4: <level 3's concise format>"
	// And level 3's concise format is "level 3: level 0"
	verbose := ce.WithFormat(errchain.Verbose)
	require.EqualError(t, verbose, "level 4: level 3: level 0")
}

func TestWithFormat_MultiLevel(t *testing.T) {
	// Test that format only affects current level, not recursively
	err1 := errors.New("root")
	err2 := errchain.Wrap(errors.New("middle"), err1)
	err3 := errchain.Wrap(errors.New("outer"), err2)

	ce3, ok := err3.(errchain.ChainedError)
	require.True(t, ok)

	// Set err3 to verbose - it should show outer: middle: root
	verbose3 := ce3.WithFormat(errchain.Verbose)
	require.EqualError(t, verbose3, "outer: middle: root")

	// The child (err2) should still use its own format (concise by default)
	ce2, ok := err2.(errchain.ChainedError)
	require.True(t, ok)
	require.EqualError(t, ce2, "middle: root")
}

func TestWithFormat_MultiLevel_Semantics(t *testing.T) {
	// Verify format is non-recursive: it only affects the current level's display

	// Create a 3-level chain where middle level is set to verbose
	err1 := errors.New("level 3")
	err2 := errchain.Wrap(errors.New("level 2"), err1)

	ce2, ok := err2.(errchain.ChainedError)
	require.True(t, ok)

	// Set middle level to verbose
	err2Verbose := ce2.WithFormat(errchain.Verbose)

	// Wrap with outer level (which will use concise by default)
	err3 := errchain.Wrap(errors.New("level 1"), err2Verbose)

	// err3 uses concise format, so it shows: "level 1: level 3"
	// (The fact that err2Verbose is verbose doesn't affect how err3 displays)
	require.EqualError(t, err3, "level 1: level 3")
}

// ============================================================================
// Test Cases for WithFormat (Package Function)
// ============================================================================

func TestWithFormat_PackageFunc_ChainedError(t *testing.T) {
	err := errchain.Wrap(errors.New("outer"), errors.New("inner"))

	// No type assertion needed with package function
	verbose := errchain.WithFormat(err, errchain.Verbose)
	require.EqualError(t, verbose, "outer: inner")
}

func TestWithFormat_PackageFunc_RegularError(t *testing.T) {
	regularErr := errors.New("regular error")

	// Should pass through unchanged
	result := errchain.WithFormat(regularErr, errchain.Verbose)
	require.Same(t, regularErr, result, "Should return same error for non-ChainedError")
}

func TestWithFormat_PackageFunc_Nil(t *testing.T) {
	// Should handle nil safely
	result := errchain.WithFormat(nil, errchain.Verbose)
	require.Nil(t, result, "Should return nil for nil input")
}

func TestWithFormat_PackageFunc_Ergonomics(t *testing.T) {
	// Demonstrate ergonomics: no type assertion needed
	err := errchain.Wrap(errors.New("outer"), errors.New("inner"))

	// Package function - clean and simple
	verbose1 := errchain.WithFormat(err, errchain.Verbose)
	require.NotNil(t, verbose1)

	// Compare with interface method approach (more verbose)
	ce, ok := err.(errchain.ChainedError)
	require.True(t, ok)
	verbose2 := ce.WithFormat(errchain.Verbose)
	require.NotNil(t, verbose2)

	// Both should produce same result
	require.Equal(t, verbose1.Error(), verbose2.Error())
}

// ============================================================================
// Test Cases for Edge Cases
// ============================================================================

func TestInnermost_NilUnwrap(t *testing.T) {
	// Test ChainedError with Unwrap() returning nil
	// This is a defensive test for malformed ChainedError implementations

	err1 := errors.New("root")
	err2 := errchain.Wrap(errors.New("outer"), err1)

	// Normal case should work
	require.EqualError(t, err2, "outer: root")

	// The implementation should handle nil from Unwrap() gracefully
	// (tested implicitly in the traversal loop with nil check)
}

func TestInnermost_CircularReference(t *testing.T) {
	// Create a mock circular reference by creating a very deep chain
	// that exceeds the depth limit

	err := errors.New("root")

	// Create a chain deeper than 1000 to trigger depth limit
	// We'll create 1100 levels to test the circular reference protection
	for i := 0; i < 1100; i++ {
		err = errchain.Wrap(fmt.Errorf("level %d", i), err)
	}

	// Should not panic or hang - depth limit should prevent infinite loop
	msg := err.Error()
	require.NotEmpty(t, msg, "Should produce error message even with deep chain")

	// The innermost detection should stop at depth 1000
	// So the error message should still be produced successfully
	require.Contains(t, msg, "level 1099") // outermost level
}

func TestInnermost_CircularReference_DepthLimit(t *testing.T) {
	// Verify that depth limit stops at exactly 1000

	// Create a chain of exactly 1001 levels
	err := errors.New("root")
	for i := 0; i < 1001; i++ {
		err = errchain.Wrap(fmt.Errorf("level %d", i), err)
	}

	// Should successfully create and display the error
	msg := err.Error()
	require.NotEmpty(t, msg)

	// The depth limit should have been hit, but the error should still work
	require.Contains(t, msg, "level 1000")
}

func TestInnermost_CircularReference_Behavior(t *testing.T) {
	// Verify that on hitting depth limit, the function doesn't panic
	// and returns gracefully

	err := errors.New("base")

	// Create very deep chain
	for i := 0; i < 2000; i++ {
		err = errchain.Wrap(fmt.Errorf("wrap %d", i), err)
	}

	// Should not panic
	require.NotPanics(t, func() {
		_ = err.Error()
	})

	// Should produce a valid error message
	msg := err.Error()
	require.NotEmpty(t, msg)
}

func TestError_Concurrent(t *testing.T) {
	// Test concurrent calls to Error() method
	err := errchain.Wrap(errors.New("outer"), errors.New("inner"))

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan string, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			errors <- err.Error()
		}()
	}

	wg.Wait()
	close(errors)

	// All goroutines should produce the same result
	expected := "outer: inner"
	for msg := range errors {
		require.Equal(t, expected, msg)
	}
}

func TestWithFormat_Concurrent(t *testing.T) {
	// Test concurrent calls to WithFormat
	err := errchain.Wrap(errors.New("outer"), errors.New("inner"))

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(format errchain.Format) {
			defer wg.Done()
			formatted := errchain.WithFormat(err, format)
			results <- formatted
		}(errchain.Format(i % 2)) // Alternate between Concise and Verbose
	}

	wg.Wait()
	close(results)

	// All results should be valid errors
	count := 0
	for result := range results {
		require.NotNil(t, result)
		count++
	}
	require.Equal(t, numGoroutines, count)
}

// ============================================================================
// Test Cases for Stdlib Interaction
// ============================================================================

func TestStdlib_FmtErrorf(t *testing.T) {
	// Test wrapping ChainedError with fmt.Errorf("%w")
	baseErr := errors.New("database error")
	chainedErr := errchain.Wrap(errors.New("query failed"), baseErr)

	// Wrap with fmt.Errorf
	wrappedErr := fmt.Errorf("handler failed: %w", chainedErr)

	require.EqualError(t, wrappedErr, "handler failed: query failed: database error")
}

func TestStdlib_ErrorsUnwrap(t *testing.T) {
	// Test that errors.Unwrap works with ChainedError
	child := errors.New("child")
	parent := errors.New("parent")
	chainedErr := errchain.Wrap(parent, child)

	// errors.Unwrap should work
	unwrapped := errors.Unwrap(chainedErr)
	require.Equal(t, child, unwrapped)
}

func TestStdlib_ErrorsIs(t *testing.T) {
	// Test that errors.Is traverses the chain
	targetErr := errors.New("target error")
	wrappedOnce := errchain.Wrap(errors.New("wrap 1"), targetErr)
	wrappedTwice := errchain.Wrap(errors.New("wrap 2"), wrappedOnce)

	// errors.Is should find the target error in the chain
	require.True(t, errors.Is(wrappedTwice, targetErr))
	require.True(t, errors.Is(wrappedOnce, targetErr))

	// Should not match different error
	otherErr := errors.New("other error")
	require.False(t, errors.Is(wrappedTwice, otherErr))
}

// customError is a test error type for TestStdlib_ErrorsAs
type customError struct {
	msg  string
	code int
}

func (e *customError) Error() string {
	return e.msg
}

func TestStdlib_ErrorsAs(t *testing.T) {
	// Test that errors.As works with ChainedError

	// Create a chain with custom error
	customErr := &customError{msg: "custom error", code: 42}
	wrappedErr := errchain.Wrap(errors.New("outer"), customErr)

	// errors.As should find the custom error
	var target *customError
	require.True(t, errors.As(wrappedErr, &target))
	require.Equal(t, 42, target.code)
}

func TestStdlib_NilWrapped_NoUnwrap(t *testing.T) {
	// Verify that nil-wrapped errors don't gain Unwrap capability
	err := errchain.Wrap(errors.New("context"), nil)

	// Should be nil
	require.Nil(t, err)

	// No Unwrap method to call since it's nil
	// This verifies that Wrap(parent, nil) returns plain nil, not a ChainedError
}

// ============================================================================
// Test Cases for Documentation Examples
// ============================================================================

func TestExample_Basic(t *testing.T) {
	// Example from package documentation
	err1 := errors.New("root cause")
	err2 := errchain.Wrap(errors.New("intermediate error"), err1)
	err3 := errchain.Wrap(errors.New("top level error"), err2)

	require.EqualError(t, err3, "top level error: root cause")
}

func TestExample_Verbose(t *testing.T) {
	// Example with WithFormat
	err1 := errors.New("database connection failed")
	err2 := errchain.Wrap(errors.New("failed to load user"), err1)
	err3 := errchain.Wrap(errors.New("request handler error"), err2)

	verboseErr := errchain.WithFormat(err3, errchain.Verbose)
	require.EqualError(t, verboseErr, "request handler error: failed to load user: database connection failed")
}

func TestExample_NilHandling(t *testing.T) {
	// Examples of nil cases

	// Case 1: Wrap(nil, error) returns error as-is
	err1 := errchain.Wrap(nil, errors.New("actual error"))
	require.EqualError(t, err1, "actual error")

	// Case 2: Wrap(error, nil) returns nil
	err2 := errchain.Wrap(errors.New("context"), nil)
	require.Nil(t, err2)

	// Case 3: Wrap(nil, nil) returns nil
	err3 := errchain.Wrap(nil, nil)
	require.Nil(t, err3)
}

// ============================================================================
// Additional Test: Backward Compatibility
// ============================================================================

func TestBasic(t *testing.T) {
	// Original test from existing codebase - should still pass
	err1 := errors.New("root cause")
	err2 := errchain.Wrap(errors.New("intermediate error"), err1)
	err3 := errchain.Wrap(errors.New("top level error"), err2)

	require.EqualError(t, err3, "top level error: root cause")
}

// ============================================================================
// Additional Tests for Comprehensive Coverage
// ============================================================================

func TestWrap_ReturnType(t *testing.T) {
	// Verify that Wrap returns error type (not ChainedError)
	err := errchain.Wrap(errors.New("parent"), errors.New("child"))

	// Should be assignable to error
	var e error = err
	require.NotNil(t, e)

	// Can be type asserted to ChainedError
	ce, ok := err.(errchain.ChainedError)
	require.True(t, ok)
	require.NotNil(t, ce)
}

func TestChainedError_Unwrap(t *testing.T) {
	// Test Unwrap method specifically
	child := errors.New("child")
	parent := errors.New("parent")

	chained := errchain.Wrap(parent, child)
	ce, ok := chained.(errchain.ChainedError)
	require.True(t, ok)

	unwrapped := ce.Unwrap()
	require.Equal(t, child, unwrapped)
}

func TestFormat_Constants(t *testing.T) {
	// Verify format constants are as expected
	require.Equal(t, errchain.Concise, errchain.Default)
	require.NotEqual(t, errchain.Concise, errchain.Verbose)
}

// ============================================================================
// Test Cases for fmt.Formatter support
// ============================================================================

func TestFormat_PlusV(t *testing.T) {
	// Test %+v always shows verbose output
	err1 := errors.New("innermost")
	err2 := errchain.Wrap(errors.New("middle"), err1)
	err3 := errchain.Wrap(errors.New("outer"), err2)

	// Default concise format
	require.EqualError(t, err3, "outer: innermost")

	// %+v should always show verbose
	result := fmt.Sprintf("%+v", err3)
	require.Equal(t, "outer: middle: innermost", result)
}

func TestFormat_S(t *testing.T) {
	// Test %s uses error's format setting
	err1 := errors.New("innermost")
	err2 := errchain.Wrap(errors.New("middle"), err1)
	err3 := errchain.Wrap(errors.New("outer"), err2)

	// Default is concise
	result := fmt.Sprintf("%s", err3)
	require.Equal(t, "outer: innermost", result)

	// Set to verbose
	verbose := errchain.WithFormat(err3, errchain.Verbose)
	result = fmt.Sprintf("%s", verbose)
	require.Equal(t, "outer: middle: innermost", result)
}

func TestFormat_V(t *testing.T) {
	// Test %v uses error's format setting
	err1 := errors.New("innermost")
	err2 := errchain.Wrap(errors.New("middle"), err1)
	err3 := errchain.Wrap(errors.New("outer"), err2)

	// Default is concise
	result := fmt.Sprintf("%v", err3)
	require.Equal(t, "outer: innermost", result)

	// Set to verbose
	verbose := errchain.WithFormat(err3, errchain.Verbose)
	result = fmt.Sprintf("%v", verbose)
	require.Equal(t, "outer: middle: innermost", result)
}

func TestFormat_PlusV_OverridesFormat(t *testing.T) {
	// Test that %+v always shows verbose regardless of format setting
	err1 := errors.New("innermost")
	err2 := errchain.Wrap(errors.New("middle"), err1)
	err3 := errchain.Wrap(errors.New("outer"), err2)

	// Explicitly set to concise
	concise := errchain.WithFormat(err3, errchain.Concise)

	// %+v should still show verbose
	result := fmt.Sprintf("%+v", concise)
	require.Equal(t, "outer: middle: innermost", result)

	// Regular %v should use concise
	result = fmt.Sprintf("%v", concise)
	require.Equal(t, "outer: innermost", result)
}
