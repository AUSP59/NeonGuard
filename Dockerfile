
FROM alpine:3.22 AS build
RUN apk add --no-cache build-base cmake openssl-dev
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DNEONSEC_WITH_TLS=ON && cmake --build build -j && cmake --install build --prefix /usr/local

FROM gcr.io/distroless/cc-debian12
COPY --from=build /usr/local/bin/neonsec /usr/local/bin/neonsec
USER 65532:65532
HEALTHCHECK CMD ["/usr/local/bin/neonsec","--help"]
ENTRYPOINT ["/usr/local/bin/neonsec"]
CMD ["--help"]
