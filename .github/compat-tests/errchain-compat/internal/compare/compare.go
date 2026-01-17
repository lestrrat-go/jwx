package compare

import (
	"errors"
	"fmt"
	"strings"
)

// ComparisonResult represents the result of comparing two errors
type ComparisonResult struct {
	TestName      string
	CheckType     string // "errors.Is", "errors.Unwrap", "message"
	Passed        bool
	V3012Value    string
	ErrchainValue string
	Details       string
}

// CompareErrorIs checks if both errors match the target error using errors.Is()
func CompareErrorIs(testName string, v3012Err, errchainErr, target error) ComparisonResult {
	v3012Matches := errors.Is(v3012Err, target)
	errchainMatches := errors.Is(errchainErr, target)

	passed := v3012Matches == errchainMatches

	result := ComparisonResult{
		TestName:      testName,
		CheckType:     "errors.Is",
		Passed:        passed,
		V3012Value:    fmt.Sprintf("%t", v3012Matches),
		ErrchainValue: fmt.Sprintf("%t", errchainMatches),
	}

	if !passed {
		result.Details = fmt.Sprintf("errors.Is() behavior differs: v3.0.12=%t, errchain=%t for target %T",
			v3012Matches, errchainMatches, target)
	} else {
		result.Details = fmt.Sprintf("errors.Is() behavior matches: both=%t", v3012Matches)
	}

	return result
}

// CompareUnwrap checks if both errors unwrap the same number of times
func CompareUnwrap(testName string, v3012Err, errchainErr error) ComparisonResult {
	v3012Depth := countUnwrapDepth(v3012Err)
	errchainDepth := countUnwrapDepth(errchainErr)

	passed := v3012Depth == errchainDepth

	result := ComparisonResult{
		TestName:      testName,
		CheckType:     "errors.Unwrap",
		Passed:        passed,
		V3012Value:    fmt.Sprintf("%d", v3012Depth),
		ErrchainValue: fmt.Sprintf("%d", errchainDepth),
	}

	if !passed {
		result.Details = fmt.Sprintf("Unwrap chain depth differs: v3.0.12=%d levels, errchain=%d levels",
			v3012Depth, errchainDepth)
	} else {
		result.Details = fmt.Sprintf("Unwrap chain depth matches: both=%d levels", v3012Depth)
	}

	return result
}

// CompareVisibleDepth checks if both errors have the same visible error depth
// (number of error message segments separated by ": ")
func CompareVisibleDepth(testName string, v3012Err, errchainErr error) ComparisonResult {
	v3012Depth := countVisibleErrorDepth(v3012Err)
	errchainDepth := countVisibleErrorDepth(errchainErr)

	passed := v3012Depth == errchainDepth

	result := ComparisonResult{
		TestName:      testName,
		CheckType:     "visible_depth",
		Passed:        passed,
		V3012Value:    fmt.Sprintf("%d", v3012Depth),
		ErrchainValue: fmt.Sprintf("%d", errchainDepth),
	}

	if !passed {
		result.Details = fmt.Sprintf("Visible error depth differs: v3.0.12=%d segments, errchain=%d segments",
			v3012Depth, errchainDepth)
	} else {
		result.Details = fmt.Sprintf("Visible error depth matches: both=%d segments", v3012Depth)
	}

	return result
}

// CompareMessageSemantics checks if both error messages contain operation context and root cause
// Note: This does NOT check for exact string equality, only semantic equivalence
func CompareMessageSemantics(testName string, v3012Err, errchainErr error, expectedContext string) ComparisonResult {
	if v3012Err == nil && errchainErr == nil {
		return ComparisonResult{
			TestName:      testName,
			CheckType:     "message",
			Passed:        true,
			V3012Value:    "nil",
			ErrchainValue: "nil",
			Details:       "Both errors are nil",
		}
	}

	if v3012Err == nil || errchainErr == nil {
		return ComparisonResult{
			TestName:      testName,
			CheckType:     "message",
			Passed:        false,
			V3012Value:    errorString(v3012Err),
			ErrchainValue: errorString(errchainErr),
			Details:       "One error is nil, the other is not",
		}
	}

	v3012Msg := v3012Err.Error()
	errchainMsg := errchainErr.Error()

	// Check if both contain expected context (e.g., "jwt.Parse", "jwt.Validate")
	v3012HasContext := expectedContext == "" || strings.Contains(v3012Msg, expectedContext)
	errchainHasContext := expectedContext == "" || strings.Contains(errchainMsg, expectedContext)

	// Get the root causes
	v3012Root := getRootError(v3012Err)
	errchainRoot := getRootError(errchainErr)

	// Check if both messages reference the root cause
	// This is a heuristic - we check if some words from root appear in the message
	v3012HasRoot := containsRootInfo(v3012Msg, v3012Root)
	errchainHasRoot := containsRootInfo(errchainMsg, errchainRoot)

	passed := v3012HasContext && errchainHasContext && v3012HasRoot && errchainHasRoot

	result := ComparisonResult{
		TestName:      testName,
		CheckType:     "message",
		Passed:        passed,
		V3012Value:    v3012Msg,
		ErrchainValue: errchainMsg,
	}

	if !passed {
		issues := []string{}
		if !v3012HasContext {
			issues = append(issues, fmt.Sprintf("v3.0.12 missing context '%s'", expectedContext))
		}
		if !errchainHasContext {
			issues = append(issues, fmt.Sprintf("errchain missing context '%s'", expectedContext))
		}
		if !v3012HasRoot {
			issues = append(issues, "v3.0.12 missing root cause info")
		}
		if !errchainHasRoot {
			issues = append(issues, "errchain missing root cause info")
		}
		result.Details = strings.Join(issues, "; ")
	} else {
		result.Details = "Message semantics preserved: both contain context and root cause"
	}

	return result
}

// countUnwrapDepth counts how many times an error can be unwrapped
func countUnwrapDepth(err error) int {
	if err == nil {
		return 0
	}

	depth := 0
	current := err

	for {
		unwrapped := errors.Unwrap(current)
		if unwrapped == nil {
			break
		}
		depth++
		current = unwrapped

		// Safety limit to prevent infinite loops
		if depth > 100 {
			break
		}
	}

	return depth
}

// countVisibleErrorDepth counts the number of error message segments
// by splitting on ": " delimiter. For example:
// "jws.Verify: err 1: err 2" has a depth of 3
func countVisibleErrorDepth(err error) int {
	if err == nil {
		return 0
	}

	msg := err.Error()
	if msg == "" {
		return 0
	}

	// Count segments by splitting on ": "
	// This represents the visible nesting depth in the error message
	segments := 1
	for i := 0; i < len(msg)-1; i++ {
		if msg[i] == ':' && msg[i+1] == ' ' {
			segments++
			i++ // Skip the space after colon
		}
	}

	return segments
}

// getRootError gets the innermost error in a chain
func getRootError(err error) error {
	if err == nil {
		return nil
	}

	current := err
	for {
		unwrapped := errors.Unwrap(current)
		if unwrapped == nil {
			return current
		}
		current = unwrapped
	}
}

// containsRootInfo checks if the message contains information from the root error
func containsRootInfo(message string, root error) bool {
	if root == nil {
		return true
	}

	rootMsg := root.Error()
	if rootMsg == "" {
		return true
	}

	// Simple heuristic: check if significant words from root appear in message
	// Split root message into words and check if any appear in the full message
	words := strings.Fields(rootMsg)
	for _, word := range words {
		// Skip very short words
		if len(word) < 4 {
			continue
		}
		// Check if this word appears in the message
		if strings.Contains(strings.ToLower(message), strings.ToLower(word)) {
			return true
		}
	}

	// Also check if root message appears directly
	return strings.Contains(message, rootMsg)
}

// errorString returns string representation of error, handling nil
func errorString(err error) string {
	if err == nil {
		return "nil"
	}
	return err.Error()
}
