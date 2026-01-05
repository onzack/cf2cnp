# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o cf2cnp ./cmd/cf2cnp

# Runtime stage - using distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

# Copy binary from builder
COPY --from=builder /app/cf2cnp /cf2cnp

# Expose port
EXPOSE 8080

# Run the server
ENTRYPOINT ["/cf2cnp"]
CMD ["serve", "--port", "8080"]
