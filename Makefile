VERIFY_TARGET=testMbedtlsVerify
SIGN_TARGET=testMbedtlsSign
MBEDTLS_DIR=mbedtls/library
MBEDTLS_LIB_NAME=mbedcrypto
MBEDTLS_LIB_VERIFY=$(MBEDTLS_DIR)/lib$(MBEDTLS_LIB_NAME).a
MBEDTLS_LIB_SIGN=$(MBEDTLS_DIR)/lib$(MBEDTLS_LIB_NAME).a
MBEDTLS_INC=mbedtls/include
MBEDTLS_CONFIG_FILE="mbedtls/rently_mbedtls_config.h"

VERIFY_SRC = \
    verify.c

SIGN_SRC = \
	sign.c

all: $(VERIFY_TARGET) #$(SIGN_TARGET)

.PHONY: $(MBEDTLS_LIB_NAME)

$(VERIFY_TARGET): $(VERIFY_SRC) $(MBEDTLS_LIB_VERIFY)
	$(CC) -o $@ $(VERIFY_SRC) -L$(MBEDTLS_DIR) -l$(MBEDTLS_LIB_NAME) -I$(MBEDTLS_INC)

$(SIGN_TARGET): $(SIGN_SRC) $(MBEDTLS_LIB_SIGN)

$(MBEDTLS_LIB_VERIFY): $(MBEDTLS_LIB_NAME)
	$(MAKE) -C $(MBEDTLS_DIR) CFLAGS=-DMBEDTLS_CONFIG_FILE=$(MBEDTLS_CONFIG_FILE)

$(MBEDTLS_LIB_SIGN): $(MBEDTLS_LIB_NAME)
	$(MAKE) -C $(MBEDTLS_DIR) 