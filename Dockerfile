ARG REPO=github.com/cilium/ariane

FROM golang:1.25@sha256:f60eaa87c79e604967c84d18fd3b151b3ee3f033bcdade4f3494e38411e60963 AS builder
ARG REPO
WORKDIR /go/src/${REPO}/
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/ariane

FROM gcr.io/distroless/static-debian12:latest@sha256:87bce11be0af225e4ca761c40babb06d6d559f5767fbf7dc3c47f0f1a466b92c
ARG REPO

COPY --from=builder /usr/local/bin/ariane /usr/local/bin/ariane
EXPOSE 8080
CMD ["/usr/local/bin/ariane"]
