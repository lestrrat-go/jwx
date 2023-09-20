# Comparison Benchmarks

## Parsing signed JWT

* github.com/lestrrat-go/jwx/v2
* github.com/golang-jwt/jwt

```
go test -bench . -benchmem -tags jwx_goccy | tee goccy.txt
goos: linux
goarch: amd64
pkg: github.com/lestrrat-go/jwx/v3/bench/comparison
cpu: AMD Ryzen 9 3900X 12-Core Processor
BenchmarkJWT/github.com/lestrrat-go/jwx/v2-24                   100          10606620 ns/op         6094200 B/op      39411 allocs/op
BenchmarkJWT/github.com/golang-jwt/jwt-24                    100          10577532 ns/op         6080878 B/op      39366 allocs/op
```
