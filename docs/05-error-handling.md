# Error Handling

All packages in `github.com/lestrrat-go/jwx/v3` use consistent error handling pattern. Once you understand how error handling works in one package, you should be able to apply the same pattern across all other packages in the library.

As of v3.1.0, the error handling system in `github.com/lestrrat-go/jwx/v3` has been revised and designed to be concise by default, but allow querying for details. Specifically, by default only the broadest and the most specific error messages are displayed. You can either use `"%+v"` format specifier to display the entire error chain, or use `errors.Is()/errors.As()` and `errors.Unwrap()` to query for a specific error type.

## Error Types and Sentinels

Each package in `github.com/lestrrat-go/jwx/v3` provides sentinel errors that represent specific error conditions. Please look for functions that return these opaque error values such as `jwt.ParseError()`, `jws.VerifyError()`, etc in each package to learn what's available.

These opaque error values should be compared using `errors.Is()/errors.As()` function. Never compare them directly with `==` as the internal implementation may change.

## Checking Error Types

Use the standard `errors.Is()` function to check if an error matches a specific sentinel type.

<!-- INCLUDE(examples/jwx_error_handling_type_checking_example_test.go) -->
<!-- END INCLUDE -->

The `errors.Is()` function traverses the entire error chain, checking each error in the sequence until it finds a match. If the error you're looking for is anywhere in the chain, `errors.Is()` will find it.

## Unwrapping Error Chains

All errors in `github.com/lestrrat-go/jwx/v3` support standard Go 1.13+ error unwrapping through the `errors.Unwrap()` function. When operations fail deep within the library, the error that occurred at the lowest level is wrapped with additional context as it propagates back up through the call stack.

<!-- INCLUDE(examples/jwx_error_handling_unwrap_example_test.go) -->
<!-- END INCLUDE -->

You can traverse the chain manually using `errors.Unwrap()` to inspect each level of the error. This is useful when you need to extract specific information from an error at a particular level in the chain, or when you're implementing custom error handling logic.

## Error Formatting

Errors in `github.com/lestrrat-go/jwx/v3` can be formatted using standard Go fmt package verbs. The `%s` or `%v` verbs produce the standard format. The `%+v` verb may show additional debugging information depending on the specific error and the depth of the error chain.

<!-- INCLUDE(examples/jwx_error_handling_formatting_example_test.go) -->
<!-- END INCLUDE -->

With simpler errors or shorter chains, both formats may produce similar output. For more complex error scenarios, the verbose format can provide additional context about where in a multi-step operation the failure occurred.

Use the standard format for day-to-day error logging and display. Reserve the verbose format for active debugging sessions where you need to see all available details.

## Checking Nested Error Types

Error chains in `github.com/lestrrat-go/jwx/v3` frequently contain multiple error types stacked together. Consider what happens when JWT parsing fails during validation. You might have a `jwt.ParseError()` at the outer level that wraps a `jwt.ValidateError()`. That validation error might in turn wrap a more specific error like `jwt.TokenExpiredError()`. The `errors.Is()` function can check for any of these error types in the chain, not just the outermost one.

<!-- INCLUDE(examples/jwx_error_handling_nested_types_example_test.go) -->
<!-- END INCLUDE -->

This allows you to check for errors at whatever level of specificity makes sense for your use case. Sometimes you need to know specifically that a token expired. Other times you only care that validation failed in general.

The `errors.Is()` function performs a deep traversal of the entire error chain. It checks the outer error first, then unwraps and checks the next error, continuing all the way down to the innermost error. If it finds a match at any level, it returns true.
