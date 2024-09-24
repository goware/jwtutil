# jwtutil

CLI tool for encoding/decoding JWT tokens.

## Install

```
$ brew tap goware/tap
$ brew install jwtutil
$ jwtutil
```

or

`$ docker run ghcr.io/goware/jwtutil`

or

`$ go install github.com/goware/jwtutil@latest`

## Usage

### Create JWT token
```bash
$ jwtutil -secret=besafe -encode
```

### Create JWT token with expiry (unix timestamp value)
```bash
$ jwtutil -secret=besafe -encode -exp=1585272657
```

### Create JWT token with expiry in 5 days
```bash
$ jwtutil -secret=besafe -encode -exp $(date +%s --date='5 days')
```

### Create JWT token with custom claims
```bash
$ jwtutil -secret=besafe -encode -claims='{"account":1234}'
```

### Decode JWT
```bash
$ jwtutil -secret=besafe -decode -token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50IjoxMjM0fQ.WrPyTSoovFETG6pW0wFepaAv9-VTIfeSHU5imhPqs7g'
```

## LICENSE

MIT
