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

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/mailria .

# Copy names.csv if it exists (used by the application)
COPY --from=builder /app/names.csv* ./

# Create a non-root user for security
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser && \
    chown -R appuser:appuser /app

USER appuser

# Expose port 8000 (as defined in main.go)
EXPOSE 8000

# Default command (can be overridden)
# Usage: docker run <image> server|sync|sync_sent
ENTRYPOINT ["./mailria"]

# Default to server mode
CMD ["server"]
