# Dev-sandbox: DockerfileAlpine + make web. One container, backend + frontend.
# Same logic as DockerfileAlpine, adds node/npm and make web before make zip.
FROM alpine:latest AS buildenv

ARG NO_SANITIZERS=1

RUN apk --no-cache add gcc protobuf-c-dev build-base git zip curl nodejs npm

COPY . /buildenv
WORKDIR /buildenv

RUN curl -f https://raw.githubusercontent.com/toniebox-reverse-engineering/tonies-json/release/tonies.json -o /buildenv/contrib/config/tonies.json || true
RUN curl -f https://raw.githubusercontent.com/toniebox-reverse-engineering/tonies-json/release/tonieboxes.json -o /buildenv/contrib/config/tonieboxes.json || true
RUN make web
RUN make zip NO_SANITIZERS=${NO_SANITIZERS}

FROM alpine:latest
ARG TEDDYCLOUD_VERSION=unknown
LABEL org.opencontainers.image.version=$TEDDYCLOUD_VERSION
EXPOSE 80 443 8443

RUN apk --no-cache add strace ffmpeg curl ca-certificates bash
RUN update-ca-certificates

RUN mkdir -p /teddycloud/certs \
    && mkdir /teddycloud/config \
    && mkdir -p /teddycloud/data/content/default \
    && mkdir -p /teddycloud/data/library \
    && mkdir -p /teddycloud/data/firmware  \
    && mkdir -p /teddycloud/data/www \
    && mkdir -p /teddycloud/data/www/custom_img \
    && mkdir -p /teddycloud/data/www/plugins \
    && mkdir -p /teddycloud/data/cache \
    && mkdir -p /tmp

RUN ln -s /teddycloud /etc/teddycloud

COPY --from=buildenv /buildenv/install/pre/certs/ /teddycloud/certs/
COPY --from=buildenv /buildenv/install/pre/data/www/ /teddycloud/data/www/
COPY --from=buildenv /buildenv/install/pre/*.sh /usr/local/bin/
COPY --from=buildenv /buildenv/install/pre/teddycloud /usr/local/bin/teddycloud
COPY --from=buildenv /buildenv/install/zip/release.zip /tmp/teddycloud.zip

VOLUME \
    "/teddycloud/data/content" \
    "/teddycloud/data/library" \
    "/teddycloud/data/firmware" \
    "/teddycloud/data/cache" \
    "/teddycloud/data/www/custom_img" \
    "/teddycloud/data/www/plugins" \
    "/teddycloud/certs" \
    "/teddycloud/config"

COPY docker/docker-entrypoint.sh /
RUN chmod +rx /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
