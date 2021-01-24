# Benchmarks

## Full benchmark

```
go test -bench . -benchmem
```

## Quick benchmark

```
go test -short -bench . -benchmem
```

## Switch JSON backends

```
go test -tags jwx_goccy -short -bench . -benchmem
```
