FROM ubuntu:latest AS buildenv

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc gdb protobuf-c-compiler build-essential git zip curl

#COPY . /buildenv
#WORKDIR /buildenv
#
#RUN curl -f https://raw.githubusercontent.com/toniebox-reverse-engineering/tonies-json/release/tonies.json -o /buildenv/install/pre/config/tonies.json || true
#RUN make zip