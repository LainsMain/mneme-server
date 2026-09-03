# syntax=docker/dockerfile:1.7
FROM golang:1.27-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/mneme ./cmd/mneme \
    && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="Mneme Server" \
      org.opencontainers.image.source="https://github.com/LainsMain/mneme-server" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/mneme /mneme
COPY --from=build /src/LICENSE /LICENSE
COPY --chown=65532:65532 --from=build /out/data /data
VOLUME ["/data"]
EXPOSE 8080
ENV MNEME_DATA_DIR=/data MNEME_LISTEN=:8080
ENTRYPOINT ["/mneme"]
CMD ["serve"]
