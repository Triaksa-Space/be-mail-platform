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
