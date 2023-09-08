FROM ubuntu:latest as buildenv

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc protobuf-c-compiler build-essential git \
    && rm -rf /var/lib/apt/lists/*

COPY . /buildenv
WORKDIR /buildenv
RUN make preinstall

FROM ubuntu:latest
EXPOSE 80 443

RUN apt-get update \
    && apt-get install -y --no-install-recommends faketime openssl libubsan1 ffmpeg \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /teddycloud/certs \
    && mkdir /teddycloud/config \
    && mkdir -p /teddycloud/data/content/default \
    && mkdir -p /teddycloud/data/library \
    && mkdir -p /teddycloud/data/www 

COPY --from=buildenv \
    /buildenv/install/pre/certs/ /teddycloud/certs/
COPY --from=buildenv \
    /buildenv/install/pre/data/www/ /teddycloud/data/www/

COPY --from=buildenv \
    /buildenv/install/pre/*.sh /usr/local/bin/
COPY --from=buildenv \
    /buildenv/install/pre/teddycloud /usr/local/bin/teddycloud

VOLUME \
    "/teddycloud/data/content" \
    "/teddycloud/data/library" \
    "/teddycloud/certs" \
    "/teddycloud/config"

COPY docker/docker-entrypoint.sh /usr/local/bin/
RUN chmod +rx /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
