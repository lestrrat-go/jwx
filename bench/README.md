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
% benchstat -sort -delta stdlib.txt v0.3.5.txt 

name                                                      old time/op    new time/op    delta
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-8          50.8µs ± 1%    15.3µs ± 1%   -69.95%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.Parse-8                51.4µs ± 1%    16.7µs ± 9%   -67.52%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-8          52.0µs ± 2%    17.2µs ±10%   -67.00%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-8           15.6µs ± 1%     6.1µs ± 4%   -60.68%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.Parse-8                 15.5µs ± 2%     6.2µs ± 4%   -60.27%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-8           15.1µs ± 1%     6.2µs ± 5%   -59.29%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-8           15.7µs ± 2%     6.4µs ± 2%   -59.28%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-8                 15.8µs ± 2%     6.5µs ± 3%   -58.86%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-8           15.8µs ± 1%     6.6µs ± 1%   -58.23%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-8            13.0µs ± 3%     5.7µs ± 1%   -55.77%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-8                  12.7µs ± 1%     5.6µs ± 3%   -55.69%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-8            13.1µs ± 2%     5.8µs ± 3%   -55.50%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-8                          21.9µs ± 4%     9.9µs ± 4%   -54.77%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-8                    21.7µs ± 2%    10.1µs ± 6%   -53.38%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-8                    21.6µs ± 1%    10.2µs ± 7%   -52.55%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-8     8.69µs ± 1%    4.44µs ± 1%   -48.97%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-8           8.93µs ± 3%    4.57µs ± 2%   -48.82%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-8    8.75µs ± 4%    4.52µs ± 1%   -48.30%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-8     8.83µs ± 1%    4.59µs ± 1%   -48.00%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-8          8.73µs ± 2%    4.57µs ± 2%   -47.61%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-8    8.62µs ± 2%    4.59µs ± 2%   -46.81%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-8                          10.7µs ± 5%     6.8µs ± 5%   -37.02%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-8                    10.4µs ± 4%     6.6µs ± 3%   -36.54%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-8                    8.74µs ± 3%    5.62µs ± 2%   -35.72%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-8                          8.48µs ± 1%    5.56µs ± 6%   -34.44%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-8                    8.57µs ± 1%    5.78µs ± 5%   -32.56%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-8                    10.3µs ± 1%     7.0µs ± 4%   -31.93%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-8                       4.45µs ± 8%    3.17µs ± 6%   -28.85%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-8                 4.41µs ± 3%    3.21µs ± 8%   -27.16%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseReader-8                 4.46µs ± 5%    3.35µs ±11%   -25.00%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Unmarshal-8                     4.61µs ± 3%    4.67µs ± 4%      ~     (p=0.198 n=5+5)
JWK/Serialization/RSA/PrivateKey/json.Marshal-8             15.8µs ± 2%    15.9µs ± 1%      ~     (p=0.421 n=5+5)
JWT/Serialization/Sign/jwt.Sign-8                           1.02ms ± 1%    1.00ms ± 2%      ~     (p=0.222 n=5+5)
JWT/Serialization/JSON/json.Unmarshal-8                     1.31µs ± 3%    1.34µs ± 3%      ~     (p=0.222 n=5+5)
JWK/Serialization/RSA/PublicKey/json.Marshal-8              6.08µs ± 3%    6.41µs ± 2%    +5.47%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/json.Marshal-8              6.28µs ± 2%    6.70µs ± 2%    +6.58%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/json.Marshal-8               5.43µs ± 2%    5.92µs ± 1%    +9.08%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-8        4.22µs ± 1%    4.64µs ± 1%    +9.79%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Marshal-8                       12.1µs ± 3%    13.7µs ±15%   +13.20%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Marshal-8                       3.66µs ± 5%    4.14µs ± 5%   +13.28%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-8       4.17µs ± 2%    4.76µs ± 5%   +14.31%  (p=0.008 n=5+5)
JWS/Serialization/JSON/json.Marshal-8                       12.3µs ± 1%    14.3µs ± 5%   +16.41%  (p=0.008 n=5+5)

name                                                      old alloc/op   new alloc/op   delta
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-8          36.4kB ± 0%    25.6kB ± 0%   -29.77%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.Parse-8                36.5kB ± 0%    25.6kB ± 0%   -29.73%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-8          38.3kB ± 0%    27.4kB ± 0%   -28.34%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-8                          10.5kB ± 0%     8.5kB ± 0%   -19.35%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-8                    11.0kB ± 0%     8.9kB ± 0%   -18.55%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-8                    11.0kB ± 0%     9.0kB ± 0%   -18.45%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-8                          10.1kB ± 0%     8.4kB ± 0%   -16.34%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-8                    10.1kB ± 0%     8.5kB ± 0%   -16.26%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-8                    10.6kB ± 0%     9.0kB ± 0%   -15.55%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-8                          16.3kB ± 0%    15.9kB ± 0%    -2.62%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-8                    17.2kB ± 0%    16.8kB ± 0%    -2.48%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-8                    17.9kB ± 0%    17.5kB ± 0%    -2.39%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Unmarshal-8                     1.58kB ± 0%    1.58kB ± 0%      ~     (all equal)
JWT/Serialization/JSON/json.Unmarshal-8                       592B ± 0%      592B ± 0%      ~     (all equal)
JWS/Serialization/Compact/jws.ParseReader-8                 3.34kB ± 0%    3.54kB ± 0%    +5.74%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-8                 3.02kB ± 0%    3.22kB ± 0%    +6.35%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-8                       2.83kB ± 0%    3.02kB ± 0%    +6.78%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-8           7.97kB ± 0%    8.84kB ± 0%   +10.94%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-8                 7.62kB ± 0%    8.49kB ± 0%   +11.45%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-8           7.57kB ± 0%    8.44kB ± 0%   +11.52%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-8            7.25kB ± 0%    8.09kB ± 0%   +11.59%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-8                  7.01kB ± 0%    7.85kB ± 0%   +11.99%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-8            6.96kB ± 0%    7.80kB ± 0%   +12.07%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Sign-8                           36.2kB ± 0%    40.9kB ± 0%   +12.80%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-8     6.37kB ± 0%    7.35kB ± 0%   +15.45%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-8    6.37kB ± 0%    7.35kB ± 0%   +15.45%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-8           6.24kB ± 0%    7.22kB ± 0%   +15.77%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-8          6.24kB ± 0%    7.22kB ± 0%   +15.77%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-8     6.19kB ± 0%    7.18kB ± 0%   +15.89%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-8    6.19kB ± 0%    7.18kB ± 0%   +15.89%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-8           7.60kB ± 0%    8.98kB ± 0%   +18.21%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.Parse-8                 7.18kB ± 0%    8.57kB ± 0%   +19.27%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-8           7.14kB ± 0%    8.52kB ± 0%   +19.39%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/json.Marshal-8             8.83kB ± 0%   11.15kB ± 0%   +26.33%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/json.Marshal-8              2.34kB ± 0%    4.66kB ± 0%   +99.36%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/json.Marshal-8              2.28kB ± 0%    4.61kB ± 0%  +101.80%  (p=0.016 n=5+4)
JWK/Serialization/EC/PublicKey/json.Marshal-8               1.79kB ± 0%    4.12kB ± 0%  +129.54%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Marshal-8                       3.96kB ± 0%   10.94kB ± 0%  +176.10%  (p=0.016 n=4+5)
JWS/Serialization/JSON/json.Marshal-8                       5.17kB ± 0%   14.47kB ± 0%  +179.81%  (p=0.016 n=4+5)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-8        1.15kB ± 0%    3.48kB ± 0%  +201.47%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-8       1.15kB ± 0%    3.48kB ± 0%  +201.47%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Marshal-8                         720B ± 0%     3043B ± 0%  +322.64%  (p=0.008 n=5+5)

name                                                      old allocs/op  new allocs/op  delta
JWK/Serialization/RSA/PrivateKey/jwk.ParseReader-8             204 ± 0%        92 ± 0%   -54.90%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.Parse-8                   205 ± 0%        93 ± 0%   -54.63%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/jwk.ParseString-8             206 ± 0%        94 ± 0%   -54.37%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseReader-8              128 ± 0%        64 ± 0%   -50.00%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.Parse-8                    129 ± 0%        65 ± 0%   -49.61%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/jwk.ParseString-8              130 ± 0%        66 ± 0%   -49.23%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseReader-8               111 ± 0%        58 ± 0%   -47.75%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.Parse-8                     112 ± 0%        59 ± 0%   -47.32%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/jwk.ParseString-8               113 ± 0%        60 ± 0%   -46.90%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseReader-8             95.0 ± 0%      53.0 ± 0%   -44.21%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.Parse-8                   96.0 ± 0%      54.0 ± 0%   -43.75%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/jwk.ParseString-8             97.0 ± 0%      55.0 ± 0%   -43.30%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.Parse-8                         49.0 ± 0%      29.0 ± 0%   -40.82%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseString-8                   50.0 ± 0%      30.0 ± 0%   -40.00%  (p=0.008 n=5+5)
JWS/Serialization/Compact/jws.ParseReader-8                   50.0 ± 0%      30.0 ± 0%   -40.00%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseReader-8       80.0 ± 0%      49.0 ± 0%   -38.75%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseReader-8      80.0 ± 0%      49.0 ± 0%   -38.75%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.Parse-8             81.0 ± 0%      50.0 ± 0%   -38.27%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.Parse-8            81.0 ± 0%      50.0 ± 0%   -38.27%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/jwk.ParseString-8       82.0 ± 0%      51.0 ± 0%   -37.80%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/jwk.ParseString-8      82.0 ± 0%      51.0 ± 0%   -37.80%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.Parse-8                             103 ± 0%        67 ± 0%   -34.95%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseString-8                       104 ± 0%        68 ± 0%   -34.62%  (p=0.008 n=5+5)
JWT/Serialization/Sign/jwt.ParseReader-8                       104 ± 0%        68 ± 0%   -34.62%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.Parse-8                             153 ± 0%       105 ± 0%   -31.37%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseString-8                       154 ± 0%       106 ± 0%   -31.17%  (p=0.008 n=5+5)
JWS/Serialization/JSON/jws.ParseReader-8                       155 ± 0%       107 ± 0%   -30.97%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.Parse-8                            73.0 ± 0%      58.0 ± 0%   -20.55%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseString-8                      74.0 ± 0%      59.0 ± 0%   -20.27%  (p=0.008 n=5+5)
JWT/Serialization/JSON/jwt.ParseReader-8                      74.0 ± 0%      59.0 ± 0%   -20.27%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Unmarshal-8                       26.0 ± 0%      26.0 ± 0%      ~     (all equal)
JWT/Serialization/JSON/json.Unmarshal-8                       10.0 ± 0%      10.0 ± 0%      ~     (all equal)
JWT/Serialization/Sign/jwt.Sign-8                              192 ± 0%       202 ± 0%    +5.21%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PrivateKey/json.Marshal-8               51.0 ± 0%      56.0 ± 0%    +9.80%  (p=0.008 n=5+5)
JWK/Serialization/EC/PrivateKey/json.Marshal-8                31.0 ± 0%      36.0 ± 0%   +16.13%  (p=0.008 n=5+5)
JWK/Serialization/EC/PublicKey/json.Marshal-8                 27.0 ± 0%      32.0 ± 0%   +18.52%  (p=0.008 n=5+5)
JWK/Serialization/RSA/PublicKey/json.Marshal-8                24.0 ± 0%      29.0 ± 0%   +20.83%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PublicKey/json.Marshal-8          20.0 ± 0%      25.0 ± 0%   +25.00%  (p=0.008 n=5+5)
JWK/Serialization/Symmetric/PrivateKey/json.Marshal-8         20.0 ± 0%      25.0 ± 0%   +25.00%  (p=0.008 n=5+5)
JWT/Serialization/JSON/json.Marshal-8                         18.0 ± 0%      23.0 ± 0%   +27.78%  (p=0.008 n=5+5)
JWE/Serialization/JSON/json.Marshal-8                         45.0 ± 0%      60.0 ± 0%   +33.33%  (p=0.008 n=5+5)
JWS/Serialization/JSON/json.Marshal-8                         60.0 ± 0%      80.0 ± 0%   +33.33%  (p=0.008 n=5+5)
```
