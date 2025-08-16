# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o bin/aimessage-server ./cmd/aimessage-server

# Production stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/bin/aimessage-server .

# Create data directory
RUN mkdir -p data

EXPOSE 8080

CMD ["./aimessage-server"]
