# -----------------------------------------------------------------
# Builder
# -----------------------------------------------------------------
FROM golang:1.22.0-alpine3.19 as builder
ARG VERSION

RUN apk add --update git

ADD ./ /src

WORKDIR /src
RUN go build -ldflags="-s -w -X github.com/goware/jwtutil.VERSION=${VERSION}" -o /usr/bin/jwtutil .

# -----------------------------------------------------------------
# Runner
# -----------------------------------------------------------------
FROM alpine:3.19

ENV TZ=UTC

RUN apk add --no-cache --update ca-certificates

COPY --from=builder /usr/bin/jwtutil /usr/bin/

ENTRYPOINT ["/usr/bin/jwtutil"]
