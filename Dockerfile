ARG REPO=github.com/cilium/ariane

FROM golang:1.26@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS builder
ARG REPO
WORKDIR /go/src/${REPO}/
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/ariane

FROM gcr.io/distroless/static-debian12:latest@sha256:a9fcaedd4c9b59e12dd65d954f0b5044f19b0647a8a3712e77205df9e7b102cd
ARG REPO

COPY --from=builder /usr/local/bin/ariane /usr/local/bin/ariane
EXPOSE 8080
CMD ["/usr/local/bin/ariane"]
