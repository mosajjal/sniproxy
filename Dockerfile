FROM --platform=${TARGETPLATFORM:-linux/amd64} golang:1.26-alpine
LABEL maintainer="Ali Mosajjal <hi@n0p.me>"

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache git
RUN mkdir /app
ADD . /app/
WORKDIR /app/cmd/sniproxy
ENV CGO_ENABLED=0
# opt-in Go 1.26 experiments: runtime goroutine leak profile, and the v2
# encoding/json implementation. Both become the default in Go 1.27.
ENV GOEXPERIMENT=goroutineleakprofile,jsonv2
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOFLAGS=-buildvcs=false go build -ldflags "-s -w -X main.version=$(git describe --tags) -X main.commit=$(git rev-parse HEAD)" -o sniproxy .
CMD ["/app/cmd/sniproxy/sniproxy"]

FROM scratch
COPY --from=0 /app/cmd/sniproxy/sniproxy /sniproxy
ENTRYPOINT ["/sniproxy"]
