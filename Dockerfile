FROM golang:1.18 as builder

WORKDIR /app

COPY go.* ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 go build -v -o server

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/server /app/server

EXPOSE 8443
CMD ["/app/server"]