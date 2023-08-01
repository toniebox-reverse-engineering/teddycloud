#!/bin/bash

CA_KEY="certs/server/ca-key.pem"
CA_CRT="certs/server/ca-root.pem"
DAYS="9000"
KEY_LEN="4096"
FAKETIME="2015-11-03 00:00:00"

# Check input parameters
if [ $# -ne 2 ]; then
  echo "Usage: ./script.sh <box-mac> <box-name>"
  exit 1
fi

box_mac="$1"
box_name="$2"

# Check box-mac format
if [[ ! $box_mac =~ ^[0-9a-fA-F]{12}$ ]]; then
  echo "Error: Box MAC should be in format 001122334455"
  exit 1
fi

# Check if faketime is installed
if ! command -v faketime &> /dev/null; then
  echo "faketime is not installed. Please install it to proceed."
  exit 1
fi


# Setup directories and file paths
BOX_DIR="certs/box/$box_name"
mkdir -p $BOX_DIR
CL_KEY="${BOX_DIR}/private.der"
CL_CRT="${BOX_DIR}/client.der"
CL_CA_DER="${BOX_DIR}/ca.der"
CL_CSR="${BOX_DIR}/box.csr"
CL_KEY_PEM="${BOX_DIR}/key.pem"
CL_CRT_PEM="${BOX_DIR}/cert.pem"

# Create client certificate
echo "Generate client certificate"
faketime "${FAKETIME}" openssl genrsa -out ${CL_KEY_PEM} ${KEY_LEN}
faketime "${FAKETIME}" openssl req -new -key ${CL_KEY_PEM} -out ${CL_CSR} -sha256 -subj "/C=DE/CN=b'${box_mac}'/O=TeddyCloud"
faketime "${FAKETIME}" openssl x509 -req -in ${CL_CSR} -CA ${CA_CRT} -CAkey ${CA_KEY} -CAcreateserial -out ${CL_CRT_PEM} -days ${DAYS} -sha256

# Convert to DER format
echo "create ${CL_KEY}"
openssl rsa -in ${CL_KEY_PEM} -outform der -out ${CL_KEY}
echo "create ${CL_CRT}"
openssl x509 -outform der -in ${CL_CRT_PEM} -out ${CL_CRT}
echo "create ${CL_CA_DER}"
openssl x509 -outform der -in ${CA_CRT} -out ${CL_CA_DER}

# cleanup
rm ${CL_CSR}
rm ${CL_KEY_PEM}
rm ${CL_CRT_PEM}

