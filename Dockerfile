# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application binary
# Note: The same binary is used for server, sync, and sync_sent modes
# The mode is determined by command line arguments
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mailria cmd/main.go

# Final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/mailria .
COPY --from=builder /app/names.csv* ./

# copy migrations + entrypoint
COPY migrations ./migrations
COPY docker/entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

# install goose (pick ONE approach)
# A) download prebuilt binary (common)
RUN wget -qO /usr/local/bin/goose https://github.com/pressly/goose/releases/download/v3.22.1/goose_linux_x86_64 && \
    chmod +x /usr/local/bin/goose

# non-root user (same as yours)
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
CMD ["server"]
