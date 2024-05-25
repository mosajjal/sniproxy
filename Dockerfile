FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.22.3-alpine3.20

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

LABEL maintainer "Ali Mosajjal <hi@n0p.me>"
RUN apk add --no-cache git
RUN mkdir /app
ADD . /app/
WORKDIR /app/cmd/sniproxy
ENV CGO_ENABLED=0
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOFLAGS=-buildvcs=false go build -ldflags "-s -w -X main.version=$(git describe --tags) -X main.commit=$(git rev-parse HEAD)" -o sniproxy .
CMD ["/app/cmd/sniproxy/sniproxy"]

FROM scratch
COPY --from=0 /app/cmd/sniproxy/sniproxy /sniproxy
ENTRYPOINT ["/sniproxy"]
