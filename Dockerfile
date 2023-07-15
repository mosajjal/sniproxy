FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.20.6-alpine3.18

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

LABEL maintainer "Ali Mosajjal <hi@n0p.me>"
RUN apk add --no-cache git
RUN mkdir /app
ADD . /app/
WORKDIR /app
ENV CGO_ENABLED=0
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOFLAGS=-buildvcs=false go build -ldflags "-s -w -X main.version=$(git describe --tags) -X main.commit=$(git rev-parse HEAD)" -o sniproxy .
CMD ["/app/sniproxy"]

FROM scratch
COPY --from=0 /app/sniproxy /sniproxy
ENTRYPOINT ["/sniproxy"]
