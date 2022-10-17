FROM golang:1.19.2-alpine3.16
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
