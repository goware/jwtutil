# -----------------------------------------------------------------
# Builder
# -----------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.22.0-alpine3.19 as builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

RUN apk add --update git

ADD ./ /src

WORKDIR /src
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w -X main.VERSION=${VERSION}" -o /usr/bin/jwtutil .

# -----------------------------------------------------------------
# Runner
# -----------------------------------------------------------------
FROM alpine:3.19

ENV TZ=UTC

RUN apk add --no-cache --update ca-certificates

COPY --from=builder /usr/bin/jwtutil /usr/bin/

ENTRYPOINT ["/usr/bin/jwtutil"]
