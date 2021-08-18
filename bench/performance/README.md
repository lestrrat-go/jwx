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

Go 1.6.2, github.com/goccy/go-json v0.7.4

```
benchstat -sort -delta stdlib.txt goccy.txt
name                                                       old time/op    new time/op    delta
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-24          75.1µs ± 3%    29.3µs ± 2%  -60.98%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.Parse-24                73.3µs ± 1%    28.8µs ± 1%  -60.65%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-24          75.2µs ± 0%    30.0µs ± 1%  -60.09%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-24           29.6µs ± 2%    14.4µs ± 0%  -51.38%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-24                    39.1µs ± 2%    19.1µs ± 1%  -51.13%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-24                 28.7µs ± 1%    14.3µs ± 1%  -50.09%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-24                          38.6µs ± 5%    19.3µs ± 2%  -49.90%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-24                    38.5µs ± 0%    19.3µs ± 2%  -49.87%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-24           28.8µs ± 1%    14.6µs ± 2%  -49.35%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.Parse-24                 26.5µs ± 0%    13.5µs ± 0%  -49.00%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-24           26.8µs ± 1%    13.7µs ± 1%  -48.76%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-24           26.9µs ± 0%    14.0µs ± 1%  -48.00%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-24                  24.2µs ± 0%    12.7µs ± 2%  -47.72%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-24            24.4µs ± 0%    12.8µs ± 2%  -47.64%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-24            24.5µs ± 0%    13.1µs ± 2%  -46.70%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-24           19.0µs ± 1%    10.9µs ± 1%  -42.51%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-24     19.3µs ± 1%    11.3µs ± 3%  -41.22%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-24    19.2µs ± 1%    11.4µs ± 1%  -40.63%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-24     19.4µs ± 1%    11.6µs ± 2%  -40.34%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-24          18.9µs ± 2%    11.4µs ± 1%  -39.91%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-24    19.3µs ± 1%    11.7µs ± 1%  -39.59%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-24                          21.6µs ± 2%    15.2µs ± 0%  -29.84%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-24                       11.1µs ± 1%     7.8µs ± 2%  -29.51%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseReader-24                 11.7µs ± 2%     8.3µs ± 3%  -29.22%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-24                    21.8µs ± 1%    15.6µs ± 1%  -28.58%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-24                 11.7µs ± 1%     8.3µs ± 2%  -28.57%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-24                    21.8µs ± 1%    15.6µs ± 1%  -28.25%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-24                          14.6µs ± 1%    10.7µs ± 1%  -26.92%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-24                    14.9µs ± 1%    11.0µs ± 1%  -26.36%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-24                    14.6µs ± 0%    10.8µs ± 2%  -26.04%  (p=0.016 n=4+5)
JWS/Serialization/JSON/json.Marshal-24                       29.8µs ± 4%    28.3µs ± 2%   -4.98%  (p=0.016 n=5+5)
JWE/Serialization/JSON/json.Marshal-24                       33.5µs ± 3%    34.4µs ± 1%     ~     (p=0.056 n=5+5)
JWK/Serialization/EC/PublicKey/json.Marshal-24               14.7µs ± 5%    15.3µs ± 1%     ~     (p=0.095 n=5+5)
JWK/Serialization/EC/PrivateKey/json.Marshal-24              16.0µs ± 5%    15.9µs ± 2%     ~     (p=1.000 n=5+5)
JWT/Serialization/Sign/jwt.Sign-24                           1.22ms ± 0%    1.22ms ± 1%     ~     (p=0.690 n=5+5)
JWK/Serialization/RSA/PublicKey/json.Marshal-24              14.7µs ± 1%    15.0µs ± 1%   +2.10%  (p=0.016 n=5+5)
JWK/Serialization/RSA/PrivateKey/json.Marshal-24             27.9µs ± 1%    28.8µs ± 1%   +3.13%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Unmarshal-24                     4.80µs ± 0%    4.97µs ± 3%   +3.62%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Marshal-24                       11.0µs ± 1%    11.5µs ± 3%   +4.19%  (p=0.016 n=5+5)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-24        12.1µs ± 2%    12.7µs ± 2%   +4.68%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Unmarshal-24                     8.86µs ± 0%    9.29µs ± 1%   +4.84%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-24       12.0µs ± 0%    12.9µs ± 4%   +7.46%  (p=0.008 n=5+5)

name                                                       old alloc/op   new alloc/op   delta
JWT/Serialization/JSON/jwt.Parse-24                          7.80kB ± 0%    3.48kB ± 0%  -55.38%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-24                    7.85kB ± 0%    3.53kB ± 0%  -55.05%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-24                    8.31kB ± 0%    3.99kB ± 0%  -51.97%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-24                          10.8kB ± 0%     5.7kB ± 0%  -47.68%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-24                    11.3kB ± 0%     6.1kB ± 0%  -45.78%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-24                    11.4kB ± 0%     6.2kB ± 0%  -45.53%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.Parse-24                36.5kB ± 0%    26.0kB ± 0%  -28.82%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-24                       2.83kB ± 0%    2.02kB ± 0%  -28.81%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-24          38.3kB ± 0%    27.8kB ± 0%  -27.47%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-24                 3.02kB ± 0%    2.21kB ± 0%  -26.98%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-24                  7.04kB ± 0%    5.15kB ± 0%  -26.82%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-24           6.27kB ± 0%    4.64kB ± 0%  -26.02%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-24          6.27kB ± 0%    4.64kB ± 0%  -26.02%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-24            7.28kB ± 0%    5.39kB ± 0%  -25.93%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-24          41.1kB ± 0%    30.6kB ± 0%  -25.58%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-24     6.40kB ± 0%    4.77kB ± 0%  -25.50%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-24    6.40kB ± 0%    4.77kB ± 0%  -25.50%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-24            7.55kB ± 0%    5.66kB ± 0%  -25.00%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-24                          16.3kB ± 0%    12.3kB ± 0%  -24.65%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseReader-24                 3.34kB ± 0%    2.53kB ± 0%  -24.40%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-24                 7.65kB ± 0%    5.79kB ± 0%  -24.27%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-24     6.78kB ± 0%    5.15kB ± 0%  -24.06%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-24    6.78kB ± 0%    5.15kB ± 0%  -24.06%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-24                    17.2kB ± 0%    13.2kB ± 0%  -23.36%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-24           8.00kB ± 0%    6.14kB ± 0%  -23.20%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-24           8.16kB ± 0%    6.30kB ± 0%  -22.75%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-24                    17.9kB ± 0%    13.9kB ± 0%  -22.52%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.Parse-24                 7.22kB ± 0%    5.71kB ± 0%  -20.84%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-24           7.63kB ± 0%    6.13kB ± 0%  -19.71%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-24           7.73kB ± 0%    6.22kB ± 0%  -19.46%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Unmarshal-24                     1.58kB ± 0%    1.58kB ± 0%     ~     (all equal)
JWT/Serialization/Sign/jwt.Sign-24                           36.6kB ± 0%    36.6kB ± 0%     ~     (p=0.548 n=5+5)
JWT/Serialization/JSON/json.Unmarshal-24                       592B ± 0%      592B ± 0%     ~     (all equal)
JWE/Serialization/JSON/json.Marshal-24                       3.98kB ± 0%    3.99kB ± 0%   +0.24%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/json.Marshal-24               1.80kB ± 0%    1.80kB ± 0%   +0.26%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-24        1.16kB ± 0%    1.16kB ± 0%   +0.26%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-24       1.16kB ± 0%    1.16kB ± 0%   +0.26%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/json.Marshal-24             8.85kB ± 0%    8.87kB ± 0%   +0.27%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Marshal-24                         722B ± 0%      724B ± 0%   +0.28%  (p=0.008 n=5+5)
JWS/Serialization/JSON/json.Marshal-24                       5.18kB ± 0%    5.20kB ± 0%   +0.28%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/json.Marshal-24              2.34kB ± 0%    2.35kB ± 0%   +0.28%  (p=0.016 n=5+4)
JWK/Serialization/EC/PrivateKey/json.Marshal-24              2.29kB ± 0%    2.29kB ± 0%   +0.29%  (p=0.016 n=4+5)

name                                                       old allocs/op  new allocs/op  delta
JWK/Serialization/RSA/PrivateKey/jwk.Parse-24                   205 ± 0%        89 ± 0%  -56.59%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-24             206 ± 0%        90 ± 0%  -56.31%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-24             209 ± 0%        93 ± 0%  -55.50%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-24                    129 ± 0%        60 ± 0%  -53.49%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-24              130 ± 0%        61 ± 0%  -53.08%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-24              130 ± 0%        61 ± 0%  -53.08%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-24                     112 ± 0%        54 ± 0%  -51.79%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-24               113 ± 0%        55 ± 0%  -51.33%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-24               113 ± 0%        55 ± 0%  -51.33%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.Parse-24                   96.0 ± 0%      50.0 ± 0%  -47.92%  (p=0.008 n=5+5)

JWK/Serialization/RSA/PublicKey/jwk.ParseString-24             97.0 ± 0%      51.0 ± 0%  -47.42%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-24             97.0 ± 0%      51.0 ± 0%  -47.42%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-24                         49.0 ± 0%      27.0 ± 0%  -44.90%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-24                   50.0 ± 0%      28.0 ± 0%  -44.00%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseReader-24                   50.0 ± 0%      28.0 ± 0%  -44.00%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-24             81.0 ± 0%      47.0 ± 0%  -41.98%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-24            81.0 ± 0%      47.0 ± 0%  -41.98%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-24       82.0 ± 0%      48.0 ± 0%  -41.46%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-24       82.0 ± 0%      48.0 ± 0%  -41.46%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-24      82.0 ± 0%      48.0 ± 0%  -41.46%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-24      82.0 ± 0%      48.0 ± 0%  -41.46%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-24                             106 ± 0%        66 ± 0%  -37.74%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-24                       107 ± 0%        67 ± 0%  -37.38%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-24                       107 ± 0%        67 ± 0%  -37.38%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-24                             153 ± 0%       100 ± 0%  -34.64%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-24                       154 ± 0%       101 ± 0%  -34.42%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-24                       155 ± 0%       102 ± 0%  -34.19%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-24                            57.0 ± 0%      39.0 ± 0%  -31.58%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-24                      58.0 ± 0%      40.0 ± 0%  -31.03%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-24                      58.0 ± 0%      40.0 ± 0%  -31.03%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Marshal-24                         45.0 ± 0%      45.0 ± 0%     ~     (all equal)
JWE/Serialization/JSON/json.Unmarshal-24                       26.0 ± 0%      26.0 ± 0%     ~     (all equal)
JWK/Serialization/RSA/PublicKey/json.Marshal-24                24.0 ± 0%      24.0 ± 0%     ~     (all equal)
JWK/Serialization/RSA/PrivateKey/json.Marshal-24               51.0 ± 0%      51.0 ± 0%     ~     (all equal)
JWK/Serialization/EC/PublicKey/json.Marshal-24                 27.0 ± 0%      27.0 ± 0%     ~     (all equal)
JWK/Serialization/EC/PrivateKey/json.Marshal-24                31.0 ± 0%      31.0 ± 0%     ~     (all equal)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-24          20.0 ± 0%      20.0 ± 0%     ~     (all equal)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-24         20.0 ± 0%      20.0 ± 0%     ~     (all equal)
JWS/Serialization/JSON/json.Marshal-24                         60.0 ± 0%      60.0 ± 0%     ~     (all equal)
JWT/Serialization/Sign/jwt.Sign-24                              199 ± 0%       199 ± 0%     ~     (all equal)
JWT/Serialization/JSON/json.Unmarshal-24                       10.0 ± 0%      10.0 ± 0%     ~     (all equal)
JWT/Serialization/JSON/json.Marshal-24                         18.0 ± 0%      18.0 ± 0%     ~     (all equal)
```
