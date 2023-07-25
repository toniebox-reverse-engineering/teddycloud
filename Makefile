BINARY ?= bin/teddycloud

PLATFORM=linux

INCLUDES = \
	-Iinclude \
	-Iinclude/protobuf-c \
	-Isrc/proto \
	-Isrc/cyclone/common \
	-Isrc/cyclone/cyclone_tcp \
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
	cyclone/cyclone_tcp/http/http_client.c \
	cyclone/cyclone_tcp/http/http_client_misc.c \
	cyclone/cyclone_tcp/http/http_client_transport.c \
	cyclone/cyclone_tcp/http/http_common.c \
	cyclone/cyclone_tcp/http/http_server.c \
	cyclone/cyclone_tcp/http/http_server_misc.c \
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

# remove cyclone sources for which modifications exist
CYCLONE_SOURCES := $(filter-out \
	cyclone/common/debug.c \
	cyclone/cyclone_tcp/http/http_server.c \
	cyclone/cyclone_tcp/http/http_server_misc.c \
	, $(CYCLONE_SOURCES))

# and add modified ones
CYCLONE_SOURCES += \
	src/cyclone/common/debug.c \
	src/cyclone/cyclone_tcp/http/http_server.c \
	src/cyclone/cyclone_tcp/http/http_server_misc.c


LIBS = -lpthread

OBJ_DIR = obj
SRC_DIR = src


CFLAGS += -Wall -Werror
CFLAGS += -ggdb
#CFLAGS += -fsanitize=address -static-libasan -Og
CFLAGS += -D GPL_LICENSE_TERMS_ACCEPTED
CFLAGS += -D TRACE_COLORED
CFLAGS += -D TRACE_NOPATH_FILE
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
	@echo "[${GREEN}PROTO${NC} ] ${CYAN}$<${NC}"
	$(QUIET)protoc-c --c_out=$(PROTO_GEN_DIR) $< || (echo "[ ${YELLOW}LD${NC} ] Failed: ${RED}protoc-c --c_out=$(PROTO_GEN_DIR) $<${NC}"; false)

SOURCES += $(PROTO_C_FILES)
HEADERS += $(PROTO_H_FILES)
CLEAN_FILES += $(PROTO_C_FILES) $(PROTO_H_FILES)


OBJECTS = $(foreach C,$(SOURCES),$(addprefix $(OBJ_DIR)/,$(C:.c=.o)))
CLEAN_FILES += $(OBJECTS)

CYAN=\033[0;36m
RED=\033[0;31m
YELLOW=\033[0;33m
GREEN=\033[0;32m
NC=\033[0m

ifeq ($(VERBOSE),1)
  QUIET=
else
  QUIET=@
endif


all: check_dependencies build

build: $(BINARY)

.PHONY: check_dependencies
check_dependencies:
	@which protoc-c >/dev/null || (echo "${RED}Error:${NC} protoc-c not found. Install it using:" && \
	echo "  ${CYAN}Ubuntu/Debian:${NC} sudo apt-get install protobuf-c-compiler" && \
	echo "  ${CYAN}Alpine:${NC} apk add protobuf" && \
	exit 1)
	@which gcc >/dev/null || (echo "${RED}Error:${NC} gcc not found. Install it using:" && \
	echo "  ${CYAN}Ubuntu/Debian:${NC} sudo apt-get install gcc" && \
	echo "  ${CYAN}Alpine:${NC} apk add gcc" && \
	exit 1)
	@which openssl >/dev/null || (echo "${YELLOW}Warning:${NC} openssl not found, required for generating certificates. Install it using:" && \
	echo "  ${CYAN}Ubuntu/Debian:${NC} sudo apt-get install openssl" && \
	echo "  ${CYAN}Alpine:${NC} apk add openssl")
	@which faketime >/dev/null || (echo "${YELLOW}Warning:${NC} faketime not found, required for generating certificates. Install it using:" && \
	echo "  ${CYAN}Ubuntu/Debian:${NC} sudo apt-get install faketime" && \
	echo "  ${CYAN}Alpine:${NC} apk add faketime")

$(BINARY): $(OBJECTS) $(HEADERS) $(THIS_MAKEFILE)
	@echo "[ ${YELLOW}LINK${NC} ] ${CYAN}$@${NC}"
	$(QUIET)mkdir -p $(@D)
	$(QUIET)$(CC) $(CFLAGS) $(OBJECTS) $(LIBS) -o $@ || (echo "[ ${YELLOW}LD${NC} ] Failed: ${RED}$(CC) $(CFLAGS) $(OBJECTS) $(LIBS) -o $@${NC}"; false)
	$(QUIET)cp -r $(CONTRIB_DIR)/www .
	$(QUIET)mkdir -p certs/server
	$(QUIET)mkdir -p certs/client
	$(QUIET)mkdir -p config

$(OBJ_DIR)/%.o: %.c $(HEADERS) $(THIS_MAKEFILE)
	@echo "[ ${GREEN}CC${NC}   ] ${CYAN}$<${NC}"
	$(QUIET)mkdir -p $(@D)
	$(QUIET)$(CC) $(CFLAGS) -c $< -o $@ || (echo "[ ${GREEN}CC${NC} ] Failed: ${RED}$(CC) $(CFLAGS) -c $< -o $@${NC}"; false)

clean:
	@echo "[${GREEN}CLEAN${NC} ] Deleting output files..."
	$(QUIET)rm -f $(BINARY)
	$(QUIET)$(foreach O,$(CLEAN_FILES),rm -f $(O);)
	$(QUIET)rm -rf $(INSTALL_DIR)/

preinstall: clean build
	@echo "[ ${GREEN}PRE${NC}  ] Preinstall"
	$(QUIET)mkdir $(INSTALL_DIR)/
	$(QUIET)mkdir $(PREINSTALL_DIR)/
	$(QUIET)cp $(BIN_DIR)/* $(PREINSTALL_DIR)/
	$(QUIET)cp -r $(CONTRIB_DIR)/* $(PREINSTALL_DIR)/
	$(QUIET)cd $(PREINSTALL_DIR)/ \
		&& find . -name ".gitkeep" -type f -delete \
		&& cd -

zip: preinstall
	mkdir $(ZIP_DIR)/
	cd $(PREINSTALL_DIR)/ \
		&& zip -r ../../$(ZIP_DIR)/release.zip * \
		&& cd -

scan-build: clean
	mkdir -p report
	scan-build -o report make -j

.PHONY: auto
auto:
	@echo "Entering ${CYAN}auto rebuild mode${NC}. Press Ctrl-C to exit."
	@last_build_time=$$(date +%s); \
	echo "[ ${CYAN}AUTO${NC} ] Clean up"; \
	screen -ls | grep teddycloud_auto | awk '{print $$1}' | xargs -I % screen -X -S % quit; \
	echo "[ ${CYAN}AUTO${NC} ] Build"; \
	make --no-print-directory -j; \
	screen -S teddycloud_auto -dm; \
	screen -S teddycloud_auto -X screen bash -c 'valgrind $(BINARY); exec sh'; \
	while true; do \
		modified_time=$$(stat -c "%Y" $(SOURCES) $(HEADERS) $(PROTO_FILES) $(THIS_MAKEFILE) | sort -r | head -n 1); \
		if [ "$$modified_time" -gt "$$last_build_time" ]; then \
			echo "[ ${CYAN}AUTO${NC} ] Detected file change. Terminating process."; \
			screen -S teddycloud_auto -X stuff "^C"; \
			echo "[ ${CYAN}AUTO${NC} ] Rebuild"; \
			make --no-print-directory -j; \
			last_build_time=$$(date +%s); \
			screen -S teddycloud_auto -X screen bash -c 'valgrind $(BINARY); exec sh'; \
			echo "[ ${CYAN}AUTO${NC} ] Done"; \
		fi; \
		sleep 1; \
	done
