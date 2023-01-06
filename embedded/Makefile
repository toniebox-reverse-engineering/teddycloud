BINARY ?= teddycloud

PLATFORM=linux

INCLUDES = \
	-Iinclude \
	-Icyclone/common \
	-Icyclone/cyclone_ssl \
	-Icyclone/cyclone_tcp \
	-Icyclone/cyclone_crypto \
	-Icyclone/cyclone_crypto/pkix

SOURCES = \
	src/main.c \
	src/cloud_request.c \
	src/platform_$(PLATFORM).c \
	cyclone/common/cpu_endian.c \
	cyclone/common/os_port_posix.c \
	cyclone/common/date_time.c \
	cyclone/common/debug.c \
	cyclone/common/str.c \
	cyclone/cyclone_tcp/http/http_client.c \
	cyclone/cyclone_tcp/http/http_client_misc.c \
	cyclone/cyclone_tcp/http/http_client_transport.c \
	cyclone/cyclone_tcp/http/http_common.c \
	cyclone/cyclone_ssl/tls.c \
	cyclone/cyclone_ssl/tls_cipher_suites.c \
	cyclone/cyclone_ssl/tls_handshake.c \
	cyclone/cyclone_ssl/tls_client.c \
	cyclone/cyclone_ssl/tls_client_fsm.c \
	cyclone/cyclone_ssl/tls_client_extensions.c \
	cyclone/cyclone_ssl/tls_client_misc.c \
	cyclone/cyclone_ssl/tls_server.c \
	cyclone/cyclone_ssl/tls_server_fsm.c \
	cyclone/cyclone_ssl/tls_server_extensions.c \
	cyclone/cyclone_ssl/tls_server_misc.c \
	cyclone/cyclone_ssl/tls_common.c \
	cyclone/cyclone_ssl/tls_extensions.c \
	cyclone/cyclone_ssl/tls_certificate.c \
	cyclone/cyclone_ssl/tls_signature.c \
	cyclone/cyclone_ssl/tls_key_material.c \
	cyclone/cyclone_ssl/tls_transcript_hash.c \
	cyclone/cyclone_ssl/tls_cache.c \
	cyclone/cyclone_ssl/tls_ticket.c \
	cyclone/cyclone_ssl/tls_ffdhe.c \
	cyclone/cyclone_ssl/tls_record.c \
	cyclone/cyclone_ssl/tls_record_encryption.c \
	cyclone/cyclone_ssl/tls_record_decryption.c \
	cyclone/cyclone_ssl/tls_misc.c \
	cyclone/cyclone_crypto/hash/sha1.c \
	cyclone/cyclone_crypto/hash/sha256.c \
	cyclone/cyclone_crypto/mac/hmac.c \
	cyclone/cyclone_crypto/cipher/aes.c \
	cyclone/cyclone_crypto/cipher_modes/cbc.c \
	cyclone/cyclone_crypto/aead/ccm.c \
	cyclone/cyclone_crypto/aead/gcm.c \
	cyclone/cyclone_crypto/xof/keccak.c \
	cyclone/cyclone_crypto/xof/shake.c \
	cyclone/cyclone_crypto/pkc/dh.c \
	cyclone/cyclone_crypto/pkc/rsa.c \
	cyclone/cyclone_crypto/pkc/dsa.c \
	cyclone/cyclone_crypto/ecc/ec.c \
	cyclone/cyclone_crypto/ecc/ec_curves.c \
	cyclone/cyclone_crypto/ecc/ecdh.c \
	cyclone/cyclone_crypto/ecc/ecdsa.c \
	cyclone/cyclone_crypto/ecc/eddsa.c \
	cyclone/cyclone_crypto/mpi/mpi.c \
	cyclone/cyclone_crypto/encoding/base64.c \
	cyclone/cyclone_crypto/encoding/asn1.c \
	cyclone/cyclone_crypto/encoding/oid.c \
	cyclone/cyclone_crypto/pkix/pem_import.c \
	cyclone/cyclone_crypto/pkix/pem_export.c \
	cyclone/cyclone_crypto/pkix/pkcs8_key_parse.c \
	cyclone/cyclone_crypto/pkix/pkcs8_key_format.c \
	cyclone/cyclone_crypto/pkix/x509_key_format.c \
	cyclone/cyclone_crypto/pkix/x509_key_parse.c \
	cyclone/cyclone_crypto/pkix/x509_cert_parse.c \
	cyclone/cyclone_crypto/pkix/x509_cert_validate.c \
	cyclone/cyclone_crypto/pkix/x509_crl_parse.c \
	cyclone/cyclone_crypto/pkix/x509_crl_validate.c \
	cyclone/cyclone_crypto/pkix/x509_common.c \
	cyclone/cyclone_crypto/pkix/x509_signature.c \
	cyclone/cyclone_crypto/kdf/hkdf.c \
	cyclone/cyclone_crypto/rng/yarrow.c

HEADERS = \
	include/os_port_config.h \
	include/tls_config.h \
	include/crypto_config.h \
	cyclone/common/cpu_endian.h \
	cyclone/common/os_port.h \
	cyclone/common/os_port_posix.h \
	cyclone/common/date_time.h \
	cyclone/common/error.h \
	cyclone/common/debug.h \
	cyclone/cyclone_tcp/http/http_client.h \
	cyclone/cyclone_ssl/tls.h \
	cyclone/cyclone_ssl/tls_cipher_suites.h \
	cyclone/cyclone_ssl/tls_handshake.h \
	cyclone/cyclone_ssl/tls_client.h \
	cyclone/cyclone_ssl/tls_client_fsm.h \
	cyclone/cyclone_ssl/tls_client_extensions.h \
	cyclone/cyclone_ssl/tls_client_misc.h \
	cyclone/cyclone_ssl/tls_server.h \
	cyclone/cyclone_ssl/tls_server_fsm.h \
	cyclone/cyclone_ssl/tls_server_extensions.h \
	cyclone/cyclone_ssl/tls_server_misc.h \
	cyclone/cyclone_ssl/tls_common.h \
	cyclone/cyclone_ssl/tls_extensions.h \
	cyclone/cyclone_ssl/tls_certificate.h \
	cyclone/cyclone_ssl/tls_signature.h \
	cyclone/cyclone_ssl/tls_key_material.h \
	cyclone/cyclone_ssl/tls_transcript_hash.h \
	cyclone/cyclone_ssl/tls_cache.h \
	cyclone/cyclone_ssl/tls_ticket.h \
	cyclone/cyclone_ssl/tls_ffdhe.h \
	cyclone/cyclone_ssl/tls_record.h \
	cyclone/cyclone_ssl/tls_record_encryption.h \
	cyclone/cyclone_ssl/tls_record_decryption.h \
	cyclone/cyclone_ssl/tls_misc.h \
	cyclone/cyclone_crypto/core/crypto.h \
	cyclone/cyclone_crypto/hash/sha1.h \
	cyclone/cyclone_crypto/hash/sha256.h \
	cyclone/cyclone_crypto/mac/hmac.h \
	cyclone/cyclone_crypto/cipher/aes.h \
	cyclone/cyclone_crypto/cipher_modes/cbc.h \
	cyclone/cyclone_crypto/aead/ccm.h \
	cyclone/cyclone_crypto/aead/gcm.h \
	cyclone/cyclone_crypto/pkc/dh.h \
	cyclone/cyclone_crypto/pkc/rsa.h \
	cyclone/cyclone_crypto/pkc/dsa.h \
	cyclone/cyclone_crypto/ecc/ec.h \
	cyclone/cyclone_crypto/ecc/ec_curves.h \
	cyclone/cyclone_crypto/ecc/ecdh.h \
	cyclone/cyclone_crypto/ecc/ecdsa.h \
	cyclone/cyclone_crypto/ecc/eddsa.h \
	cyclone/cyclone_crypto/mpi/mpi.h \
	cyclone/cyclone_crypto/encoding/base64.h \
	cyclone/cyclone_crypto/encoding/asn1.h \
	cyclone/cyclone_crypto/encoding/oid.h \
	cyclone/cyclone_crypto/pkix/pem_export.h \
	cyclone/cyclone_crypto/pkix/pem_import.h \
	cyclone/cyclone_crypto/pkix/pkcs8_key_format.h \
	cyclone/cyclone_crypto/pkix/pkcs8_key_parse.h \
	cyclone/cyclone_crypto/pkix/x509_key_format.h \
	cyclone/cyclone_crypto/pkix/x509_key_parse.h \
	cyclone/cyclone_crypto/pkix/x509_cert_parse.h \
	cyclone/cyclone_crypto/pkix/x509_cert_validate.h \
	cyclone/cyclone_crypto/pkix/x509_crl_parse.h \
	cyclone/cyclone_crypto/pkix/x509_crl_validate.h \
	cyclone/cyclone_crypto/pkix/x509_common.h \
	cyclone/cyclone_crypto/pkix/x509_signature.h \
	cyclone/cyclone_crypto/kdf/hkdf.h \
	cyclone/cyclone_crypto/rng/yarrow.h

LIBS = -lpthread

OBJ_DIR = obj
SRC_DIR = src


CFLAGS += -Wall
CFLAGS += -D GPL_LICENSE_TERMS_ACCEPTED
CFLAGS += $(INCLUDES)

CC = gcc
LD = ld
OBJDUMP = objdump
OBJCOPY = objcopy
SIZE = size

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

all: build

build: $(BINARY)

OBJECTS = $(foreach C,$(SOURCES),$(addprefix $(OBJ_DIR)/,$(C:.c=.o)))

$(BINARY): $(OBJECTS) $(HEADERS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LIBS) -o $@

$(OBJECTS): | $(OBJ_DIR)

$(OBJ_DIR)/%.o: %.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BINARY)
	rm -f $(BINARY).map
	rm -f $(OBJ_DIR)/*.o
	$(foreach O,$(OBJECTS),rm -f $(O);)
