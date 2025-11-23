FROM golang:1.25.4-bookworm AS builder

WORKDIR /app
COPY . .
RUN apt update && apt install make -y
RUN make build

FROM gcr.io/distroless/static-debian12:debug

WORKDIR /app
COPY --from=builder /app/bin/signer /app/bin/signer

EXPOSE 8080

ENTRYPOINT ["/app/bin/signer"]
CMD ["--port", "8080"]
