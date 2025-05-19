FROM golang:1.23.5-alpine AS build

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o main



FROM alpine:3.21.3

WORKDIR /app
COPY --from=build /app/main .
ENTRYPOINT ["./main"]