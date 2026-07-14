ARG REPO=github.com/cilium/ariane

FROM golang:1.25@sha256:fb63357477ff4b1eba77af03185a0cafc475961e627cd3f78a7364ba66898187 AS builder
ARG REPO
WORKDIR /go/src/${REPO}/
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/ariane

FROM gcr.io/distroless/static-debian12:latest@sha256:22fd79fd75eab2372585b44517f8a094349938919dc613aafc37e4bdc9967c82
ARG REPO

COPY --from=builder /usr/local/bin/ariane /usr/local/bin/ariane
EXPOSE 8080
CMD ["/usr/local/bin/ariane"]
