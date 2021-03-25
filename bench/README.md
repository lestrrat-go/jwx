# Benchmarks

## Quick benchmark

```
go test -bench . -benchmem
```

## Full benchmark

```
go test -timeout 60m -bench . -benchmem | tee stdlib.txt
```

## Switch JSON backends

```
go test -timeout 60m -tags jwx_goccy -bench . -benchmem | tee goccy.txt
```

## Comparison

Go 1.6.2, github.com/goccy/go-json v0.4.8

```
benchstat -sort -delta stdlib.txt goccy.txt
name                                                      old time/op    new time/op    delta
JWK/Serialization/RSA/PrivateKey/jwk.Parse-8                52.2µs ± 6%    13.7µs ± 4%  -73.65%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-8          51.7µs ± 5%    14.0µs ± 3%  -73.00%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-8          51.9µs ± 2%    14.9µs ± 6%  -71.28%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-8           16.2µs ± 4%     5.4µs ± 4%  -66.57%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-8                 15.8µs ± 0%     5.3µs ± 0%  -66.36%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-8           16.2µs ± 3%     5.5µs ± 1%  -66.11%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.Parse-8                 15.4µs ± 5%     5.3µs ± 3%  -65.31%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-8           15.3µs ± 2%     5.3µs ± 1%  -65.24%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-8           15.2µs ± 1%     5.4µs ± 4%  -64.28%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-8                          21.2µs ± 1%     7.8µs ± 0%  -63.42%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-8                    21.4µs ± 1%     7.9µs ± 1%  -63.06%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-8                    21.8µs ± 2%     8.1µs ± 1%  -62.63%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-8                  13.1µs ± 6%     4.9µs ± 4%  -62.54%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-8            13.4µs ± 7%     5.1µs ± 4%  -61.69%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-8            13.0µs ± 3%     5.2µs ± 3%  -60.36%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-8          9.38µs ± 5%    3.97µs ± 2%  -57.65%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-8    9.68µs ±17%    4.11µs ± 1%  -57.51%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-8    9.35µs ± 4%    4.00µs ± 1%  -57.16%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-8           8.65µs ± 2%    3.90µs ± 0%  -54.97%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-8     8.83µs ± 5%    3.99µs ± 1%  -54.85%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-8     9.06µs ± 5%    4.10µs ± 1%  -54.69%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-8                       4.51µs ± 6%    2.51µs ± 1%  -44.37%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-8                    11.4µs ± 7%     6.6µs ± 1%  -42.56%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-8                 4.39µs ± 2%    2.62µs ± 1%  -40.48%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseReader-8                 4.37µs ± 1%    2.68µs ± 1%  -38.78%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-8                          8.81µs ±14%    5.41µs ± 1%  -38.56%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-8                    8.84µs ± 9%    5.56µs ± 1%  -37.14%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-8                    10.6µs ± 5%     6.8µs ± 2%  -35.91%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-8                          10.1µs ± 3%     6.5µs ± 2%  -35.45%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-8                    8.49µs ± 3%    5.54µs ± 2%  -34.71%  (p=0.008 n=5+5)
JWS/Serialization/JSON/json.Marshal-8                       12.4µs ± 6%    11.3µs ± 3%   -9.25%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Sign-8                           1.07ms ± 7%    1.00ms ± 3%   -6.54%  (p=0.032 n=5+5)
JWK/Serialization/EC/PrivateKey/json.Marshal-8              6.42µs ± 6%    6.10µs ± 0%   -4.98%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Marshal-8                       3.44µs ± 1%    3.32µs ± 0%   -3.35%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-8       4.21µs ± 3%    4.08µs ± 1%   -3.18%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Marshal-8                       12.7µs ± 6%    11.9µs ± 5%     ~     (p=0.095 n=5+5)
JWE/Serialization/JSON/json.Unmarshal-8                     4.75µs ± 4%    4.65µs ± 5%     ~     (p=0.095 n=5+5)
JWK/Serialization/RSA/PublicKey/json.Marshal-8              6.03µs ± 2%    6.18µs ±12%     ~     (p=0.841 n=5+5)
JWK/Serialization/RSA/PrivateKey/json.Marshal-8             16.0µs ± 7%    16.0µs ± 5%     ~     (p=1.000 n=5+5)
JWK/Serialization/EC/PublicKey/json.Marshal-8               5.61µs ± 5%    5.60µs ± 9%     ~     (p=0.690 n=5+5)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-8        4.33µs ± 3%    4.14µs ± 4%     ~     (p=0.056 n=5+5)
JWT/Serialization/JSON/json.Unmarshal-8                     1.29µs ± 2%    1.28µs ± 2%     ~     (p=0.841 n=5+5)

name                                                      old alloc/op   new alloc/op   delta
JWK/Serialization/RSA/PrivateKey/jwk.Parse-8                36.5kB ± 0%    23.2kB ± 0%  -36.35%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-8          38.3kB ± 0%    25.0kB ± 0%  -34.65%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-8          41.1kB ± 0%    27.8kB ± 0%  -32.28%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-8                          16.3kB ± 0%    14.8kB ± 0%   -9.48%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-8                    17.2kB ± 0%    15.7kB ± 0%   -8.99%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-8                    17.9kB ± 0%    16.3kB ± 0%   -8.67%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/json.Marshal-8             8.83kB ± 0%    8.82kB ± 0%   -0.12%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Sign-8                           36.2kB ± 0%    36.2kB ± 0%   -0.11%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Marshal-8                       3.96kB ± 0%    3.96kB ± 0%   -0.10%  (p=0.000 n=5+4)
JWS/Serialization/JSON/json.Marshal-8                       5.17kB ± 0%    5.17kB ± 0%   -0.09%  (p=0.000 n=4+5)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-8       1.15kB ± 0%    1.15kB ± 0%   -0.09%  (p=0.000 n=5+4)
JWK/Serialization/EC/PublicKey/json.Marshal-8               1.79kB ± 0%    1.79kB ± 0%   -0.06%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/json.Marshal-8              2.28kB ± 0%    2.28kB ± 0%   -0.04%  (p=0.000 n=5+4)
JWK/Serialization/RSA/PublicKey/json.Marshal-8              2.34kB ± 0%    2.34kB ± 0%   -0.04%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Unmarshal-8                     1.58kB ± 0%    1.58kB ± 0%     ~     (all equal)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-8        1.15kB ± 0%    1.15kB ± 0%     ~     (p=0.167 n=5+5)
JWT/Serialization/JSON/json.Unmarshal-8                       592B ± 0%      592B ± 0%     ~     (all equal)
JWT/Serialization/JSON/json.Marshal-8                         720B ± 0%      720B ± 0%     ~     (all equal)
JWS/Serialization/Compact/jws.ParseReader-8                 3.34kB ± 0%    3.47kB ± 0%   +3.83%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-8                 3.02kB ± 0%    3.15kB ± 0%   +4.23%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-8                       2.83kB ± 0%    2.96kB ± 0%   +4.52%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-8           8.13kB ± 0%    8.63kB ± 0%   +6.20%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-8            7.52kB ± 0%    7.99kB ± 0%   +6.28%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-8           7.97kB ± 0%    8.47kB ± 0%   +6.33%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-8            7.25kB ± 0%    7.72kB ± 0%   +6.51%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-8                 7.62kB ± 0%    8.12kB ± 0%   +6.62%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-8                  7.01kB ± 0%    7.48kB ± 0%   +6.74%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-8     6.75kB ± 0%    7.48kB ± 0%  +10.78%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-8    6.75kB ± 0%    7.48kB ± 0%  +10.78%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-8           7.70kB ± 0%    8.55kB ± 0%  +11.12%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-8           7.60kB ± 0%    8.46kB ± 0%  +11.26%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-8     6.37kB ± 0%    7.10kB ± 0%  +11.43%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-8    6.37kB ± 0%    7.10kB ± 0%  +11.43%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-8           6.24kB ± 0%    6.97kB ± 0%  +11.67%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-8          6.24kB ± 0%    6.97kB ± 0%  +11.67%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.Parse-8                 7.18kB ± 0%    8.04kB ± 0%  +11.92%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-8                    11.0kB ± 0%    12.9kB ± 0%  +16.99%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-8                    11.0kB ± 0%    12.8kB ± 0%  +17.09%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-8                          10.5kB ± 0%    12.4kB ± 0%  +17.82%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-8                    10.6kB ± 0%    12.9kB ± 0%  +21.28%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-8                    10.1kB ± 0%    12.4kB ± 0%  +22.26%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-8                          10.1kB ± 0%    12.3kB ± 0%  +22.36%  (p=0.008 n=5+5)

name                                                      old allocs/op  new allocs/op  delta
JWK/Serialization/RSA/PrivateKey/jwk.Parse-8                   205 ± 0%        84 ± 0%  -59.02%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-8             206 ± 0%        85 ± 0%  -58.74%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-8             209 ± 0%        88 ± 0%  -57.89%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-8                    129 ± 0%        60 ± 0%  -53.49%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-8              130 ± 0%        61 ± 0%  -53.08%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-8              130 ± 0%        61 ± 0%  -53.08%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-8                     112 ± 0%        54 ± 0%  -51.79%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-8               113 ± 0%        55 ± 0%  -51.33%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-8               113 ± 0%        55 ± 0%  -51.33%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.Parse-8                   96.0 ± 0%      50.0 ± 0%  -47.92%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-8             97.0 ± 0%      51.0 ± 0%  -47.42%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-8             97.0 ± 0%      51.0 ± 0%  -47.42%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-8                         49.0 ± 0%      27.0 ± 0%  -44.90%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-8                   50.0 ± 0%      28.0 ± 0%  -44.00%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseReader-8                   50.0 ± 0%      28.0 ± 0%  -44.00%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-8             81.0 ± 0%      47.0 ± 0%  -41.98%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-8            81.0 ± 0%      47.0 ± 0%  -41.98%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-8       82.0 ± 0%      48.0 ± 0%  -41.46%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-8       82.0 ± 0%      48.0 ± 0%  -41.46%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-8      82.0 ± 0%      48.0 ± 0%  -41.46%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-8      82.0 ± 0%      48.0 ± 0%  -41.46%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-8                             153 ± 0%        94 ± 0%  -38.56%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-8                       154 ± 0%        95 ± 0%  -38.31%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-8                       155 ± 0%        96 ± 0%  -38.06%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-8                             103 ± 0%        67 ± 0%  -34.95%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-8                       104 ± 0%        68 ± 0%  -34.62%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-8                       104 ± 0%        68 ± 0%  -34.62%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-8                            73.0 ± 0%      60.0 ± 0%  -17.81%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-8                      74.0 ± 0%      61.0 ± 0%  -17.57%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-8                      74.0 ± 0%      61.0 ± 0%  -17.57%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Marshal-8                         45.0 ± 0%      45.0 ± 0%     ~     (all equal)
JWE/Serialization/JSON/json.Unmarshal-8                       26.0 ± 0%      26.0 ± 0%     ~     (all equal)
JWK/Serialization/RSA/PublicKey/json.Marshal-8                24.0 ± 0%      24.0 ± 0%     ~     (all equal)
JWK/Serialization/RSA/PrivateKey/json.Marshal-8               51.0 ± 0%      51.0 ± 0%     ~     (all equal)
JWK/Serialization/EC/PublicKey/json.Marshal-8                 27.0 ± 0%      27.0 ± 0%     ~     (all equal)
JWK/Serialization/EC/PrivateKey/json.Marshal-8                31.0 ± 0%      31.0 ± 0%     ~     (all equal)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-8          20.0 ± 0%      20.0 ± 0%     ~     (all equal)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-8         20.0 ± 0%      20.0 ± 0%     ~     (all equal)
JWS/Serialization/JSON/json.Marshal-8                         60.0 ± 0%      60.0 ± 0%     ~     (all equal)
JWT/Serialization/Sign/jwt.Sign-8                              192 ± 0%       192 ± 0%     ~     (all equal)
JWT/Serialization/JSON/json.Unmarshal-8                       10.0 ± 0%      10.0 ± 0%     ~     (all equal)
JWT/Serialization/JSON/json.Marshal-8                         18.0 ± 0%      18.0 ± 0%     ~     (all equal)
```
