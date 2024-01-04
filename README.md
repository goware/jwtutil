jwtutil
=======

## Install

`go install github.com/goware/jwtutil@latest`


## Usage

**New JWT token**\
$ jwtutil -secret=besafe -encode

**New JWT token with expiry (unix timestamp value)**\
$ jwtutil -secret=besafe -encode -exp=1585272657

**New JWT token with custom claims**\
$ jwtutil -secret=besafe -encode -claims='{"account":1234}'

**Decode JWT**\
$ jwtutil -secret=besafe -decode -token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50IjoxMjM0fQ.WrPyTSoovFETG6pW0wFepaAv9-VTIfeSHU5imhPqs7g'


## LICENSE

MIT
