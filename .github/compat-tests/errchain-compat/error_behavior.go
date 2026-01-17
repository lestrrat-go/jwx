package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// TestResult captures the behavior of an error
type TestResult struct {
	TestName                 string
	ErrorOccurred            bool
	ErrorMessage             string
	IsParseError             bool
	IsValidateError          bool
	IsTokenExpired           bool
	IsTokenNotYetValid       bool
	IsInvalidIssuedAt        bool
	IsInvalidIssuer          bool
	IsInvalidAudience        bool
	IsMissingRequiredClaim   bool
	IsClaimNotFound          bool
	IsClaimAssignmentFailed  bool
	IsUnknownPayloadType     bool
	UnwrapDepth              int
	VisibleErrorDepth        int
}

func main() {
	results := []TestResult{}

	// Parse errors
	results = append(results, testParseInvalidFormat())
	results = append(results, testParseMalformedBase64())
	results = append(results, testParseMalformedJSON())
	results = append(results, testParseEmptyInput())
	results = append(results, testParseIncompleteParts())

	// Validation errors - time-based
	results = append(results, testTokenExpired())
	results = append(results, testTokenNotYetValid())
	results = append(results, testInvalidIssuedAt())

	// Validation errors - claim-based
	results = append(results, testInvalidIssuer())
	results = append(results, testInvalidAudience())
	results = append(results, testMissingRequiredClaim())

	// Claim access errors
	results = append(results, testClaimNotFound())
	results = append(results, testClaimAssignmentFailed())

	// Print results in a comparable format
	for _, r := range results {
		fmt.Printf("TEST: %s\n", r.TestName)
		fmt.Printf("  Error: %v\n", r.ErrorOccurred)
		if r.ErrorOccurred {
			fmt.Printf("  Message: %s\n", r.ErrorMessage)
			fmt.Printf("  IsParseError: %v\n", r.IsParseError)
			fmt.Printf("  IsValidateError: %v\n", r.IsValidateError)
			fmt.Printf("  IsTokenExpired: %v\n", r.IsTokenExpired)
			fmt.Printf("  IsTokenNotYetValid: %v\n", r.IsTokenNotYetValid)
			fmt.Printf("  IsInvalidIssuedAt: %v\n", r.IsInvalidIssuedAt)
			fmt.Printf("  IsInvalidIssuer: %v\n", r.IsInvalidIssuer)
			fmt.Printf("  IsInvalidAudience: %v\n", r.IsInvalidAudience)
			fmt.Printf("  IsMissingRequiredClaim: %v\n", r.IsMissingRequiredClaim)
			fmt.Printf("  IsClaimNotFound: %v\n", r.IsClaimNotFound)
			fmt.Printf("  IsClaimAssignmentFailed: %v\n", r.IsClaimAssignmentFailed)
			fmt.Printf("  IsUnknownPayloadType: %v\n", r.IsUnknownPayloadType)
			fmt.Printf("  UnwrapDepth: %d\n", r.UnwrapDepth)
			fmt.Printf("  VisibleErrorDepth: %d\n", r.VisibleErrorDepth)
		}
		fmt.Println()
	}
}

// Parse error tests

func testParseInvalidFormat() TestResult {
	result := TestResult{TestName: "Parse_InvalidFormat"}

	_, err := jwt.Parse([]byte("invalid.jwt.token"), jwt.WithVerify(false))
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsParseError = errors.Is(err, jwt.ParseError())
		result.IsValidateError = errors.Is(err, jwt.ValidateError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

func testParseMalformedBase64() TestResult {
	result := TestResult{TestName: "Parse_MalformedBase64"}

	// Invalid base64 characters
	_, err := jwt.Parse([]byte("!!!.!!!.!!!"), jwt.WithVerify(false))
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsParseError = errors.Is(err, jwt.ParseError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

func testParseMalformedJSON() TestResult {
	result := TestResult{TestName: "Parse_MalformedJSON"}

	// Valid base64 but invalid JSON
	_, err := jwt.Parse([]byte("eyJhbGciOiJub25lIn0.{invalid-json}."), jwt.WithVerify(false))
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsParseError = errors.Is(err, jwt.ParseError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

func testParseEmptyInput() TestResult {
	result := TestResult{TestName: "Parse_EmptyInput"}

	_, err := jwt.Parse([]byte(""), jwt.WithVerify(false))
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsParseError = errors.Is(err, jwt.ParseError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

func testParseIncompleteParts() TestResult {
	result := TestResult{TestName: "Parse_IncompleteParts"}

	// Only one part when expecting three
	_, err := jwt.Parse([]byte("eyJhbGciOiJub25lIn0"), jwt.WithVerify(false))
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsParseError = errors.Is(err, jwt.ParseError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

// Validation error tests - time-based

func testTokenExpired() TestResult {
	result := TestResult{TestName: "Validate_TokenExpired"}

	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(-24*time.Hour).Unix())

	err := jwt.Validate(tok)
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsParseError = errors.Is(err, jwt.ParseError())
		result.IsValidateError = errors.Is(err, jwt.ValidateError())
		result.IsTokenExpired = errors.Is(err, jwt.TokenExpiredError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

func testTokenNotYetValid() TestResult {
	result := TestResult{TestName: "Validate_TokenNotYetValid"}

	tok := jwt.New()
	tok.Set(jwt.NotBeforeKey, time.Now().Add(24*time.Hour).Unix())

	err := jwt.Validate(tok)
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsValidateError = errors.Is(err, jwt.ValidateError())
		result.IsTokenNotYetValid = errors.Is(err, jwt.TokenNotYetValidError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

func testInvalidIssuedAt() TestResult {
	result := TestResult{TestName: "Validate_InvalidIssuedAt"}

	tok := jwt.New()
	// Set iat to future time
	tok.Set(jwt.IssuedAtKey, time.Now().Add(24*time.Hour).Unix())

	err := jwt.Validate(tok)
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsValidateError = errors.Is(err, jwt.ValidateError())
		result.IsInvalidIssuedAt = errors.Is(err, jwt.InvalidIssuedAtError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

// Validation error tests - claim-based

func testInvalidIssuer() TestResult {
	result := TestResult{TestName: "Validate_InvalidIssuer"}

	tok := jwt.New()
	tok.Set(jwt.IssuerKey, "wrong-issuer")

	err := jwt.Validate(tok, jwt.WithIssuer("expected-issuer"))
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsParseError = errors.Is(err, jwt.ParseError())
		result.IsValidateError = errors.Is(err, jwt.ValidateError())
		result.IsInvalidIssuer = errors.Is(err, jwt.InvalidIssuerError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

func testInvalidAudience() TestResult {
	result := TestResult{TestName: "Validate_InvalidAudience"}

	tok := jwt.New()
	tok.Set(jwt.AudienceKey, []string{"wrong-audience"})

	err := jwt.Validate(tok, jwt.WithAudience("expected-audience"))
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsValidateError = errors.Is(err, jwt.ValidateError())
		result.IsInvalidAudience = errors.Is(err, jwt.InvalidAudienceError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

func testMissingRequiredClaim() TestResult {
	result := TestResult{TestName: "Validate_MissingRequiredClaim"}

	tok := jwt.New()
	// Don't set the required claim

	err := jwt.Validate(tok, jwt.WithRequiredClaim("custom-claim"))
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsValidateError = errors.Is(err, jwt.ValidateError())
		result.IsMissingRequiredClaim = errors.Is(err, jwt.MissingRequiredClaimError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

// Claim access error tests

func testClaimNotFound() TestResult {
	result := TestResult{TestName: "Claim_NotFound"}

	tok := jwt.New()

	var value string
	err := tok.Get("nonexistent", &value)
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsClaimNotFound = errors.Is(err, jwt.ClaimNotFoundError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

func testClaimAssignmentFailed() TestResult {
	result := TestResult{TestName: "Claim_AssignmentFailed"}

	tok := jwt.New()
	tok.Set("stringClaim", "this is a string")

	var value int
	err := tok.Get("stringClaim", &value)
	if err != nil {
		result.ErrorOccurred = true
		result.ErrorMessage = err.Error()
		result.IsClaimAssignmentFailed = errors.Is(err, jwt.ClaimAssignmentFailedError())
		result.UnwrapDepth = countUnwraps(err)
		result.VisibleErrorDepth = countVisibleErrorDepth(err)
	}

	return result
}

func countUnwraps(err error) int {
	count := 0
	for err != nil {
		err = errors.Unwrap(err)
		if err != nil {
			count++
		}
	}
	return count
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
