FROM golang:alpine 
LABEL maintainer "Ali Mosajjal <hi@n0p.me>"
RUN mkdir /app 
ADD . /app/ 
WORKDIR /app 
RUN go build -o main . 
CMD ["/app/main"]

FROM scratch
COPY --from=0 /app/main /main
ENTRYPOINT ["/main"] 
