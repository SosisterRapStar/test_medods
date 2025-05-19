FROM golang:1.23.5-alpine AS build

WORKDIR /app
COPY . .
RUN go mod download
RUN cd ./cmd && go build -o main
 



FROM alpine:3.21.3

WORKDIR /auth
COPY --from=build /app/cmd/main .
RUN touch config.yaml
ENV CONFIG_PATH=./config.yaml
ENTRYPOINT ["./main"]