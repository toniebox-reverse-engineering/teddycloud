BINARY ?= bin/teddycloud

PLATFORM=linux

INCLUDES = \
	-Iinclude \
	-Iinclude/protobuf-c \
	-Isrc/proto \
	-Icyclone/common \
	-Icyclone/cyclone_ssl \
	-Icyclone/cyclone_tcp \
	-Icyclone/cyclone_crypto \
	-Icyclone/cyclone_crypto/pkix

SOURCES = \
	$(wildcard $(SRC_DIR)/*.c) \
	$(wildcard $(SRC_DIR)/proto/*.c) \
	src/platform/platform_$(PLATFORM).c \
	$(CYCLONE_SOURCES)

HEADERS = \
	$(wildcard include/*.h) \
	$(CYCLONE_SOURCES:.c=.h)


CYCLONE_SOURCES = \
	cyclone/common/cpu_endian.c \
	cyclone/common/os_port_posix.c \
	cyclone/common/fs_port_posix.c \
	cyclone/common/date_time.c \
	cyclone/common/debug.c \
	cyclone/common/path.c \
	cyclone/common/str.c \
	cyclone/cyclone_tcp/http/mime.c \
	cyclone/cyclone_tcp/http/http_server.c \
	cyclone/cyclone_tcp/http/http_server_misc.c \
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
	cyclone/cyclone_crypto/hash/sha384.c \
	cyclone/cyclone_crypto/hash/sha512.c \
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

LIBS = -lpthread

OBJ_DIR = obj
SRC_DIR = src


CFLAGS += -Wall
CFLAGS += -ggdb
#CFLAGS += -fsanitize=address -static-libasan -Og
CFLAGS += -D GPL_LICENSE_TERMS_ACCEPTED
CFLAGS += $(INCLUDES)

CC = gcc
LD = ld
OBJDUMP = objdump
OBJCOPY = objcopy
SIZE = size

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

BIN_DIR := bin
CONTRIB_DIR := contrib
INSTALL_DIR := install
PREINSTALL_DIR := install/pre
ZIP_DIR := install/zip

# Location of your .proto files
PROTO_DIR := proto
PROTO_GEN_DIR := src/proto

# Find all .proto files in the PROTO_DIR directory
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)

# Get the corresponding .c and .h filenames
PROTO_C_FILES := $(patsubst $(PROTO_DIR)/%.proto, $(PROTO_GEN_DIR)/$(PROTO_DIR)/%.pb-c.c, $(PROTO_FILES))
PROTO_H_FILES := $(patsubst $(PROTO_DIR)/%.proto, $(PROTO_GEN_DIR)/$(PROTO_DIR)/%.pb-c.h, $(PROTO_FILES))

# Rule to build .c files from .proto files
$(PROTO_GEN_DIR)/$(PROTO_DIR)/%.pb-c.c $(PROTO_GEN_DIR)/$(PROTO_DIR)/%.pb-c.h: $(PROTO_DIR)/%.proto
	protoc-c --c_out=$(PROTO_GEN_DIR) $<

SOURCES += $(PROTO_C_FILES)
HEADERS += $(PROTO_H_FILES)

all: build

build: $(BINARY)

OBJECTS = $(foreach C,$(SOURCES),$(addprefix $(OBJ_DIR)/,$(C:.c=.o)))

$(BINARY): $(OBJECTS) $(HEADERS) $(THIS_MAKEFILE)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(OBJECTS) $(LIBS) -o $@

$(OBJ_DIR)/%.o: %.c $(HEADERS) $(THIS_MAKEFILE)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

	cp -r $(CONTRIB_DIR)/www .

clean:
	rm -f $(BINARY)
	$(foreach O,$(OBJECTS),rm -f $(O);)
	rm -rf $(INSTALL_DIR)/

preinstall: clean build
	mkdir $(INSTALL_DIR)/
	mkdir $(PREINSTALL_DIR)/
	cp $(BIN_DIR)/* $(PREINSTALL_DIR)/
	cp -r $(CONTRIB_DIR)/* $(PREINSTALL_DIR)/

zip: preinstall
	mkdir $(ZIP_DIR)/
	cd $(PREINSTALL_DIR)/ \
		&& zip -r ../../$(ZIP_DIR)/release.zip * \
		&& cd -

time_test: $(BINARY)
	$(BINARY) /v1/time

