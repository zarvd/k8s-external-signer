FROM golang:1.25.4-bookworm AS builder

WORKDIR /app
COPY . .
RUN apt update && apt install make -y
RUN make build

FROM gcr.io/distroless/static-debian12:debug

WORKDIR /app
COPY --from=builder /app/bin/signer /app/bin/signer

ENTRYPOINT ["/app/bin/signer"]
CMD ["--unix-domain-socket", "/var/run/k8s-external-signer.sock"]
