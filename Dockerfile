FROM ubuntu:latest as buildenv

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY . /buildenv
WORKDIR /buildenv
RUN make preinstall

FROM ubuntu:latest
EXPOSE 80 443

RUN apt-get update \
    && apt-get install -y --no-install-recommends faketime openssl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /teddycloud/certs/server \
    && mkdir -p /teddycloud/www/CONTENT \
    && mkdir /teddycloud/config

COPY --from=buildenv \
    /buildenv/install/pre/certs/ /teddycloud/certs/
COPY --from=buildenv \
    /buildenv/install/pre/www/ /teddycloud/www/

COPY --from=buildenv \
    /buildenv/install/pre/*.sh /usr/local/bin/
COPY --from=buildenv \
    /buildenv/install/pre/teddycloud /usr/local/bin/teddycloud

VOLUME [ \
    "/teddycloud/www/CONTENT", \
    "/teddycloud/certs", \
    "/teddycloud/config", \
    ]

COPY docker/docker-entrypoint.sh /usr/local/bin/
RUN chmod +rx /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]