FROM golang:1.18.1-alpine3.15
LABEL maintainer "Ali Mosajjal <hi@n0p.me>"
RUN apk add --no-cache git
RUN mkdir /app 
ADD . /app/ 
WORKDIR /app 
ENV CGO_ENABLED=0
RUN go build -o main . 
CMD ["/app/main"]

FROM scratch
COPY --from=0 /app/main /sniproxy
ENTRYPOINT ["/sniproxy"] 
