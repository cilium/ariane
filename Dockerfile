ARG REPO=github.com/cilium/ariane

FROM golang:1.25@sha256:d7912cedddfa15b2900a8dfb7187df0af5ec2cb424a371139b5b352fd3e6b740 AS builder
ARG REPO
WORKDIR /go/src/${REPO}/
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/ariane

FROM gcr.io/distroless/static-debian12:latest@sha256:22fd79fd75eab2372585b44517f8a094349938919dc613aafc37e4bdc9967c82
ARG REPO

COPY --from=builder /usr/local/bin/ariane /usr/local/bin/ariane
EXPOSE 8080
CMD ["/usr/local/bin/ariane"]
