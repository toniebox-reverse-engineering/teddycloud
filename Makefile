
## generic paths
BIN_DIR        = bin
OBJ_DIR        = obj
SRC_DIR        = src
CONTRIB_DIR    = contrib
INSTALL_DIR    = install
PREINSTALL_DIR = install/pre
ZIP_DIR        = install/zip

EXECUTABLE     = $(BIN_DIR)/teddycloud
LINK_LO_FILE   = $(EXECUTABLE).lo
PLATFORM      ?= linux


ifeq ($(OS),Windows_NT)
	SHELL       = cmd.exe
	ECHO        = echo
	MKDIR       = mkdir 
	RM          = del
	CP          = copy
	TO_TRASH    = >NUL 2>NUL
	# special assignment to have only the backslash in the variable
	SEP         = \$(strip)
else
	MKDIR       = mkdir -p
	ECHO        = echo -e
	RM          = rm -f
	CP          = cp
	TO_TRASH    = >/dev/null 2>&1
	SEP         = /
endif


ifeq ($(PLATFORM),linux)
	EXEC_EXT       = .so
	LINK_OUT_OPT   = -o $@
	CC_OUT_OPT     = -o
	CC_IN_OPT      = -c
	OBJ_EXT        = $(OBJ_EXT)
	LINK_LO_OPT    = @$(LINK_LO_FILE)
	LD             = $(CC)
	OBJ_EXT        = .o
endif

ifeq ($(PLATFORM),windows)
	EXEC_EXT       = .dll
	LINK_OUT_OPT   = /OUT:$@
	CC_OUT_OPT     = /Fo
	CC_IN_OPT      = /c
	OBJ_EXT        = .obj
	LINK_LO_OPT    = $(OBJ_FILES)
	OBJ_EXT        = .obj
	CPU            = x64
	ifeq ($(VCToolsVersion),)
		$(info )
		$(info   You selected windows mode, but MSVCs vcvars.bat was not started yet. )
		$(info )
		$(error   Aborting)
	endif
    CC = cl.exe
    LD = link.exe
	CFLAGS += /nologo
    LFLAGS += /LIBPATH:"$(WindowsSdkDir)\lib\$(WindowsSDKLibVersion)\um\$(VSCMD_ARG_TGT_ARCH)"
    LFLAGS += /LIBPATH:"$(WindowsSdkDir)\lib\$(WindowsSDKLibVersion)\ucrt\$(VSCMD_ARG_TGT_ARCH)"
    LFLAGS += /LIBPATH:"$(VCToolsInstallDir)\lib\$(VSCMD_ARG_TGT_ARCH)"
endif

## posix/linux specific headers/sources
HEADERS_linux = 
INCLUDES_linux = 
SOURCES_linux = \
	src/platform/platform_$(PLATFORM).c \
	cyclone/common/os_port_posix.c \
	cyclone/common/fs_port_posix.c 
LFLAGS_linux = -lpthread -lc
CFLAGS_linux += -Wall -Werror
CFLAGS_linux += -ggdb -O3

## win32 specific headers/sources
HEADERS_win32 = 
INCLUDES_win32 = 
SOURCES_win32 = \
	src/platform/platform_$(PLATFORM).c
LFLAGS_win32 = 


## generic headers/sources
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
	$(CYCLONE_SOURCES) \

HEADERS = \
	$(wildcard include/*.h) \
	$(CYCLONE_SOURCES:.c=.h)


#
# merge the platform specifics here
#
SOURCES   += $(SOURCES_$(PLATFORM))
HEADERS   += $(HEADERS_$(PLATFORM))
INCLUDES  += $(INCLUDES_$(PLATFORM))
CFLAGS    += $(CFLAGS_$(PLATFORM))
LFLAGS    += $(LFLAGS_$(PLATFORM))

CYCLONE_SOURCES = \
	cyclone/common/cpu_endian.c \
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



#CFLAGS += -fsanitize=address -static-libasan -Og
CFLAGS += -D GPL_LICENSE_TERMS_ACCEPTED
CFLAGS += -D TRACE_COLORED
CFLAGS += -D TRACE_NOPATH_FILE
CFLAGS += $(INCLUDES)

#CFLAGS += -pg
#LFLAGS += -pg -lc_p


THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))


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


OBJECTS = $(foreach C,$(SOURCES),$(addprefix $(OBJ_DIR)/,$(C:.c=$(OBJ_EXT))))
CLEAN_FILES += $(OBJECTS) $(LINK_LO_FILE)

ifeq ($(OS),Windows_NT)
CYAN=
RED=
YELLOW=
GREEN=
NC=
else
CYAN=\033[0;36m
RED=\033[0;31m
YELLOW=\033[0;33m
GREEN=\033[0;32m
NC=\033[0m
endif

ifeq ($(VERBOSE),1)
  QUIET=
else
  QUIET=@
endif


all: check_dependencies build

build: $(EXECUTABLE)

ifeq ($(OS),Windows_NT)
.PHONY: check_dependencies
check_dependencies:
else
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
endif


.PRECIOUS: %/
%/:
	$(info [DIR] creating $@)
	$(shell $(MKDIR) $(subst /,$(SEP),$@) $(TO_TRASH))

.SECONDEXPANSION:
$(LINK_LO_FILE): $$(dir $$@)
	$(file >$@, $(OBJECTS) $(OBJ_ONLY_FILES) )

.SECONDEXPANSION:
$(EXECUTABLE): $(LINK_LO_FILE) $(OBJECTS) $(HEADERS) $(THIS_MAKEFILE) certs/  certs/server/ certs/client/ config/ | $$(dir $$@)
	@$(ECHO) '[ ${YELLOW}LINK${NC} ] ${CYAN}$@${NC}'
	$(QUIET)$(LD) $(LFLAGS) $(LINK_LO_OPT) $(LINK_OUT_OPT) || ($(ECHO) '[ ${GREEN}CC${NC} ] Failed: ${RED}$(LD) $(LFLAGS) $(LINK_LO_OPT) $(LINK_OUT_OPT)${NC}'; false)
	$(QUIET)cp -r $(CONTRIB_DIR)/www .

.SECONDEXPANSION:
$(OBJ_DIR)/%$(OBJ_EXT): %.c $(HEADERS) $(THIS_MAKEFILE) | $$(dir $$@)
	@$(ECHO) '[ ${GREEN}CC${NC}   ] ${CYAN}$<${NC}'
	$(QUIET)$(CC) $(CFLAGS) $(CC_IN_OPT) $< $(CC_OUT_OPT)$@ || ($(ECHO) '[ ${GREEN}CC${NC} ] Failed: ${RED}$(CC) $(CFLAGS) $(CC_IN_OPT) $< $(CC_OUT_OPT)$@${NC}'; false)

clean:
	@$(ECHO) '[${GREEN}CLEAN${NC} ] Deleting output files...'
	$(QUIET)$(RM) $(EXECUTABLE)
	$(QUIET)$(foreach O,$(CLEAN_FILES),$(RM) $(O);)

preinstall: clean build $(INSTALL_DIR)/ $(PREINSTALL_DIR)/
	@$(ECHO) '[ ${GREEN}PRE${NC}  ] Preinstall'
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
	$(MKDIR) report
	scan-build -o report make -j

.PHONY: auto
auto:
	@$(ECHO) 'Entering ${CYAN}auto rebuild mode${NC}. Press Ctrl-C to exit.'
	@last_build_time=$$(date +%s); \
	$(ECHO) '[ ${CYAN}AUTO${NC} ] Clean up'; \
	screen -ls | grep teddycloud_auto | awk '{print $$1}' | xargs -I % screen -X -S % quit; \
	$(ECHO) '[ ${CYAN}AUTO${NC} ] Build'; \
	make --no-print-directory -j; \
	screen -S teddycloud_auto -dm; \
	screen -S teddycloud_auto -X screen bash -c 'valgrind $(EXECUTABLE); exec sh'; \
	while true; do \
		modified_time=$$(stat -c "%Y" $(SOURCES) $(HEADERS) $(PROTO_FILES) $(THIS_MAKEFILE) | sort -r | head -n 1); \
		if [ "$$modified_time" -gt "$$last_build_time" ]; then \
			$(ECHO) '[ ${CYAN}AUTO${NC} ] Detected file change. Terminating process."; \
			screen -S teddycloud_auto -X stuff "^C'; \
			$(ECHO) '[ ${CYAN}AUTO${NC} ] Rebuild'; \
			make --no-print-directory -j; \
			last_build_time=$$(date +%s); \
			screen -S teddycloud_auto -X screen bash -c 'valgrind $(EXECUTABLE); exec sh'; \
			$(ECHO) '[ ${CYAN}AUTO${NC} ] Done'; \
		fi; \
		sleep 1; \
	done
