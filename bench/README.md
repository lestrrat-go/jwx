# Benchmarks

## Quick benchmark

```
go test -bench . -benchmem
```

## Full benchmark

```
go test -timeout 30m -bench . -benchmem | tee base.txt
```

## Switch JSON backends

```
go test -timeout 30ms -tags jwx_goccy -bench . -benchmem | tee goccy.txt
```

## Comparison

```
benchstat base.txt goccy.txt
```

```
name                                                      old time/op    new time/op    delta
JWE/Serialization/JSON/json.Marshal-8                       16.2µs ± 4%    17.8µs ± 6%    +9.76%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Unmarshal-8                     4.69µs ± 5%    4.67µs ± 2%      ~     (p=1.000 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.Parse-8                 14.9µs ± 3%     6.5µs ± 5%   -56.74%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-8           15.0µs ± 1%     6.6µs ± 4%   -55.94%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-8           14.8µs ± 1%     6.4µs ± 3%   -56.93%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/json.Marshal-8              7.95µs ± 0%    8.77µs ± 7%   +10.36%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.Parse-8                49.8µs ± 1%    17.9µs ± 6%   -64.13%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-8          50.0µs ± 1%    16.9µs ±12%   -66.13%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-8          49.7µs ± 1%    17.4µs ± 7%   -65.03%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/json.Marshal-8             18.5µs ± 3%    19.9µs ± 7%    +7.53%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-8                  12.4µs ± 1%     5.9µs ± 8%   -52.50%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-8            12.6µs ± 2%     6.4µs ± 3%   -49.00%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-8            13.3µs ± 6%     6.5µs ± 1%   -51.36%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/json.Marshal-8               7.82µs ± 6%    9.58µs ± 4%   +22.56%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-8                 15.5µs ± 1%     7.5µs ± 5%   -51.51%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-8           15.6µs ± 1%     7.4µs ± 3%   -52.33%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-8           15.4µs ± 0%     7.3µs ± 0%   -52.62%  (p=0.016 n=5+4)
JWK/Serialization/EC/PrivateKey/json.Marshal-8              8.62µs ± 2%   10.65µs ± 9%   +23.58%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-8           8.79µs ± 6%    4.53µs ± 7%   -48.45%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-8     8.85µs ± 6%    4.90µs ±11%   -44.62%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-8     8.39µs ± 0%    4.99µs ±14%   -40.48%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-8        5.89µs ± 2%    6.86µs ± 8%   +16.50%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-8          8.38µs ± 1%    4.57µs ± 5%   -45.45%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-8    8.53µs ± 1%    4.50µs ± 5%   -47.32%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-8    8.44µs ± 1%    4.29µs ± 2%   -49.12%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-8       5.92µs ± 1%    6.31µs ± 2%    +6.70%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-8                       4.12µs ± 1%    2.85µs ± 1%   -30.89%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-8                 4.27µs ± 1%    2.95µs ± 0%   -30.75%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseReader-8                 4.24µs ± 1%    3.00µs ± 1%   -29.19%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-8                          21.1µs ± 2%     8.9µs ± 3%   -57.66%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-8                    21.2µs ± 1%     9.1µs ± 3%   -57.36%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-8                    21.4µs ± 0%     9.5µs ± 1%   -55.83%  (p=0.008 n=5+5)
JWS/Serialization/JSON/json.Marshal-8                       13.1µs ± 2%    14.8µs ± 2%   +12.68%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-8                    8.24µs ± 0%    5.38µs ± 1%   -34.61%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-8                          8.13µs ± 1%    5.27µs ± 2%   -35.19%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-8                    8.25µs ± 1%    5.42µs ± 1%   -34.30%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Sign-8                           1.01ms ± 2%    1.00ms ± 2%      ~     (p=0.222 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-8                    9.77µs ± 1%    6.32µs ± 2%   -35.33%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-8                          9.69µs ± 1%    6.26µs ± 1%   -35.38%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-8                    9.85µs ± 1%    6.49µs ± 1%   -34.09%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Unmarshal-8                     1.28µs ± 1%    1.26µs ± 1%    -1.75%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Marshal-8                       5.39µs ± 2%    5.97µs ± 1%   +10.68%  (p=0.008 n=5+5)

name                                                      old alloc/op   new alloc/op   delta
JWE/Serialization/JSON/json.Marshal-8                       5.84kB ± 0%   12.82kB ± 0%  +119.42%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Unmarshal-8                     1.58kB ± 0%    1.58kB ± 0%      ~     (all equal)
JWK/Serialization/RSA/PublicKey/jwk.Parse-8                 7.16kB ± 0%    8.54kB ± 0%   +19.33%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-8           7.58kB ± 0%    8.96kB ± 0%   +18.27%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-8           7.11kB ± 0%    8.50kB ± 0%   +19.46%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/json.Marshal-8              2.44kB ± 0%    4.76kB ± 0%   +95.44%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.Parse-8                36.4kB ± 0%    25.6kB ± 0%   -29.75%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-8          38.2kB ± 0%    27.4kB ± 0%   -28.35%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-8          36.4kB ± 0%    25.6kB ± 0%   -29.79%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/json.Marshal-8             9.04kB ± 0%   11.36kB ± 0%   +25.72%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-8                  6.97kB ± 0%    7.81kB ± 0%   +12.06%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-8            7.21kB ± 0%    8.05kB ± 0%   +11.65%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-8            6.92kB ± 0%    7.76kB ± 0%   +12.14%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/json.Marshal-8               1.87kB ± 0%    4.20kB ± 0%  +124.01%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-8                 7.59kB ± 0%    8.46kB ± 0%   +11.49%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-8           7.94kB ± 0%    8.82kB ± 0%   +10.98%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-8           7.54kB ± 0%    8.42kB ± 0%   +11.56%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/json.Marshal-8              2.40kB ± 0%    4.72kB ± 0%   +97.04%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-8           6.20kB ± 0%    7.18kB ± 0%   +15.87%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-8     6.33kB ± 0%    7.31kB ± 0%   +15.55%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-8     6.15kB ± 0%    7.14kB ± 0%   +15.99%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-8        1.23kB ± 0%    3.55kB ± 0%  +189.63%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-8          6.20kB ± 0%    7.18kB ± 0%   +15.87%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-8    6.33kB ± 0%    7.31kB ± 0%   +15.55%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-8    6.15kB ± 0%    7.14kB ± 0%   +15.99%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-8       1.23kB ± 0%    3.55kB ± 0%  +189.63%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-8                       2.81kB ± 0%    3.00kB ± 0%    +6.84%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-8                 3.00kB ± 0%    3.19kB ± 0%    +6.40%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseReader-8                 3.32kB ± 0%    3.51kB ± 0%    +5.78%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-8                          16.2kB ± 0%    15.8kB ± 0%    -2.63%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-8                    17.1kB ± 0%    16.7kB ± 0%    -2.49%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-8                    17.8kB ± 0%    17.4kB ± 0%    -2.40%  (p=0.008 n=5+5)
JWS/Serialization/JSON/json.Marshal-8                       5.72kB ± 0%   15.01kB ± 0%  +162.61%  (p=0.016 n=5+4)
JWT/Serialization/Sign/jwt.ParseString-8                    10.9kB ± 0%     8.9kB ± 0%   -18.59%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-8                          10.5kB ± 0%     8.4kB ± 0%   -19.39%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-8                    11.0kB ± 0%     9.0kB ± 0%   -18.49%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Sign-8                           36.3kB ± 0%    41.0kB ± 0%   +12.80%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-8                    10.1kB ± 0%     8.5kB ± 0%   -16.26%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-8                          10.1kB ± 0%     8.4kB ± 0%   -16.34%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-8                    10.6kB ± 0%     9.0kB ± 0%   -15.55%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Unmarshal-8                       592B ± 0%      592B ± 0%      ~     (all equal)
JWT/Serialization/JSON/json.Marshal-8                         800B ± 0%     3124B ± 0%  +290.30%  (p=0.008 n=5+5)

name                                                      old allocs/op  new allocs/op  delta
JWE/Serialization/JSON/json.Marshal-8                         49.0 ± 0%      64.0 ± 0%   +30.61%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Unmarshal-8                       26.0 ± 0%      26.0 ± 0%      ~     (all equal)
JWK/Serialization/RSA/PublicKey/jwk.Parse-8                   95.0 ± 0%      53.0 ± 0%   -44.21%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-8             96.0 ± 0%      54.0 ± 0%   -43.75%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-8             94.0 ± 0%      52.0 ± 0%   -44.68%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/json.Marshal-8                24.0 ± 0%      29.0 ± 0%   +20.83%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.Parse-8                   204 ± 0%        92 ± 0%   -54.90%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-8             205 ± 0%        93 ± 0%   -54.63%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-8             203 ± 0%        91 ± 0%   -55.17%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/json.Marshal-8               51.0 ± 0%      56.0 ± 0%    +9.80%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-8                     111 ± 0%        58 ± 0%   -47.75%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-8               112 ± 0%        59 ± 0%   -47.32%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-8               110 ± 0%        57 ± 0%   -48.18%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/json.Marshal-8                 27.0 ± 0%      32.0 ± 0%   +18.52%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-8                    128 ± 0%        64 ± 0%   -50.00%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-8              129 ± 0%        65 ± 0%   -49.61%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-8              127 ± 0%        63 ± 0%   -50.39%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/json.Marshal-8                31.0 ± 0%      36.0 ± 0%   +16.13%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-8             80.0 ± 0%      49.0 ± 0%   -38.75%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-8       81.0 ± 0%      50.0 ± 0%   -38.27%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-8       79.0 ± 0%      48.0 ± 0%   -39.24%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-8          20.0 ± 0%      25.0 ± 0%   +25.00%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-8            80.0 ± 0%      49.0 ± 0%   -38.75%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-8      81.0 ± 0%      50.0 ± 0%   -38.27%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-8      79.0 ± 0%      48.0 ± 0%   -39.24%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-8         20.0 ± 0%      25.0 ± 0%   +25.00%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-8                         48.0 ± 0%      28.0 ± 0%   -41.67%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-8                   49.0 ± 0%      29.0 ± 0%   -40.82%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseReader-8                   49.0 ± 0%      29.0 ± 0%   -40.82%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-8                             149 ± 0%       101 ± 0%   -32.21%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-8                       150 ± 0%       102 ± 0%   -32.00%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-8                       151 ± 0%       103 ± 0%   -31.79%  (p=0.008 n=5+5)
JWS/Serialization/JSON/json.Marshal-8                         60.0 ± 0%      80.0 ± 0%   +33.33%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-8                       103 ± 0%        67 ± 0%   -34.95%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-8                             102 ± 0%        66 ± 0%   -35.29%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-8                       103 ± 0%        67 ± 0%   -34.95%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Sign-8                              187 ± 0%       197 ± 0%    +5.35%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-8                      74.0 ± 0%      59.0 ± 0%   -20.27%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-8                            73.0 ± 0%      58.0 ± 0%   -20.55%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-8                      74.0 ± 0%      59.0 ± 0%   -20.27%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Unmarshal-8                       10.0 ± 0%      10.0 ± 0%      ~     (all equal)
JWT/Serialization/JSON/json.Marshal-8                         18.0 ± 0%      23.0 ± 0%   +27.78%  (p=0.008 n=5+5)
```
