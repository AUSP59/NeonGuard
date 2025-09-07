
FROM alpine:3.20 AS build
RUN apk add --no-cache build-base cmake
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j && cmake --install build --prefix /usr/local

FROM gcr.io/distroless/cc-debian12@sha256:1a3f4a42fa0b4f3dc75c0e0f6bc6e15f6d7b6c1ae9d1b8b1e1d9d3e2a0c5b1f0
COPY --from=build /usr/local/bin/neonsec /usr/local/bin/neonsec
USER 65532:65532
HEALTHCHECK CMD ["/usr/local/bin/neonsec","--help"]
ENTRYPOINT ["/usr/local/bin/neonsec"]
CMD ["--help"]
