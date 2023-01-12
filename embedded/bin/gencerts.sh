#!/bin/bash

CA_KEY="certs/server/ca-key.pem"
CA_CRT="certs/server/ca-root.pem"
SRV_CSR="certs/server/teddy-key.csr"
SRV_KEY="certs/server/teddy-key.pem"
SRV_CRT="certs/server/teddy-cert.pem"
DAYS="1024"

mkdir -p certs/server
openssl genrsa -aes256 -out ${CA_KEY} 2048
openssl req -x509 -new -nodes -extensions v3_ca -key ${CA_KEY} -days 1024 -out ${CA_CRT} -sha512
openssl genrsa -out ${SRV_KEY} 4096
openssl req -new -key ${SRV_KEY} -out ${SRV_CSR} -sha512
openssl x509 -req -in ${SRV_CSR} -CA ${CA_CRT} -CAkey ${CA_KEY} -CAcreateserial -out ${SRV_CRT} -days ${DAYS} -sha512
