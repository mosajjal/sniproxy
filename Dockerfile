FROM --platform=${TARGETPLATFORM:-linux/amd64} golang:alpine
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
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOFLAGS=-buildvcs=false go build -ldflags "-s -w -X main.version=$(git describe --tags) -X main.commit=$(git rev-parse HEAD)" -o sniproxy .
CMD ["/app/cmd/sniproxy/sniproxy"]

FROM scratch
COPY --from=0 /app/cmd/sniproxy/sniproxy /sniproxy
ENTRYPOINT ["/sniproxy"]
