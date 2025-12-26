#!/bin/bash

CA_KEY="certs/server/ca-key.pem"
CA_CRT="certs/server/ca-root.pem"
CA_CRT_DER="certs/server/ca.der"
SRV_CSR="certs/server/teddy-key.csr"
SRV_KEY="certs/server/teddy-key.pem"
SRV_CRT="certs/server/teddy-cert.pem"
CL_CSR="certs/client/teddy-key.csr"
CL_KEY="certs/client/teddy-key.pem"
CL_CRT="certs/client/teddy-cert.pem"
DAYS="9000"
KEY_LEN="4096"
FAKETIME="2015-11-03 00:00:00"

# Check if faketime is installed
if ! command -v faketime &> /dev/null; then
  echo "faketime is not installed. Please install it to proceed."
  exit 1
fi

mkdir -p certs/server
mkdir -p certs/client

echo "Generate CA certificate"
faketime "${FAKETIME}" openssl genrsa -out ${CA_KEY} ${KEY_LEN}
faketime "${FAKETIME}" openssl req -x509 -new -nodes -extensions v3_ca -key ${CA_KEY} -days ${DAYS} -out ${CA_CRT} -sha256 -subj '/C=DE/CN=TeddyCloud'
faketime "${FAKETIME}" openssl x509 -inform PEM -outform DER -in ${CA_CRT} -out ${CA_CRT_DER}

echo ""
echo "Generate server certificate"
faketime "${FAKETIME}" openssl genrsa -out ${SRV_KEY} ${KEY_LEN}
faketime "${FAKETIME}" openssl req -new -key ${SRV_KEY} -out ${SRV_CSR} -sha256 -subj '/C=DE/CN=TeddyCloud'
faketime "${FAKETIME}" openssl x509 -req -in ${SRV_CSR} -CA ${CA_CRT} -CAkey ${CA_KEY} -CAcreateserial -out ${SRV_CRT} -days ${DAYS} -sha256

echo ""
echo "Generate (testing) client certificate"
faketime "${FAKETIME}" openssl genrsa -out ${CL_KEY} ${KEY_LEN}
faketime "${FAKETIME}" openssl req -new -key ${CL_KEY} -out ${CL_CSR} -sha256 -subj '/C=DE/CN=TeddyCloud'
faketime "${FAKETIME}" openssl x509 -req -in ${CL_CSR} -CA ${CA_CRT} -CAkey ${CA_KEY} -CAcreateserial -out ${CL_CRT} -days ${DAYS} -sha256