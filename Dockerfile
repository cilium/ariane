ARG REPO=github.com/cilium/ariane

FROM golang:1.25@sha256:31c1e53dfc1cc2d269deec9c83f58729fa3c53dc9a576f6426109d1e319e9e9a AS builder
ARG REPO
WORKDIR /go/src/${REPO}/
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/ariane

FROM gcr.io/distroless/static-debian12:latest@sha256:4b2a093ef4649bccd586625090a3c668b254cfe180dee54f4c94f3e9bd7e381e
ARG REPO

COPY --from=builder /usr/local/bin/ariane /usr/local/bin/ariane
EXPOSE 8080
CMD ["/usr/local/bin/ariane"]
