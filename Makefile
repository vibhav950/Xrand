CC := gcc
CFLAGS := -Wpedantic -Wall -I./src/
CXXFLAGS := -std=c11 -Wall

BIN_DIR := ./bin
SRC_DIR := ./src
LOG_DIR := ./logs

MKDIR := mkdir -p
RM := rm -f

COMMON_PATH := $(SRC_DIR)/common
COMMON_SRCS := $(COMMON_PATH)/exceptions.c
COMMON_OBJS := $(BIN_DIR)/exceptions.o

JENT_PATH := $(SRC_DIR)/jitterentropy
JENT_SRCS := $(JENT_PATH)/jitterentropy-base.c \
	   		 $(JENT_PATH)/jitterentropy-gcd.c \
	   		 $(JENT_PATH)/jitterentropy-health.c \
	   		 $(JENT_PATH)/jitterentropy-noise.c \
	   		 $(JENT_PATH)/jitterentropy-sha3.c \
	   		 $(JENT_PATH)/jitterentropy-timer.c
JENT_OBJS := $(addprefix $(BIN_DIR)/, $(notdir $(JENT_SRCS:.c=.o)))
JENT_FLAGS := -O0

CRYPTO_PATH := $(SRC_DIR)/crypto
CRYPTO_SRCS := $(CRYPTO_PATH)/aes.c \
			   $(CRYPTO_PATH)/crc.c
CRYPTO_OBJS := $(addprefix $(BIN_DIR)/, $(notdir $(CRYPTO_SRCS:.c=.o)))
CRYPTO_FLAGS := -msse2 -msse -march=native -maes -O3

DEPS := -L. -lssl -lcrypto -lbcrypt

RAND_PATH := $(SRC_DIR)/rand
RAND_SRCS := $(RAND_PATH)/rdrand.c \
			 $(RAND_PATH)/rngw32.c \
			 $(RAND_PATH)/trivium.c \
			 $(RAND_PATH)/random.c
RAND_OBJS := $(addprefix $(BIN_DIR)/, $(notdir $(RAND_SRCS:.c=.o)))

EXE := $(BIN_DIR)/xrand-test

.PHONY: all
all: $(EXE) clean

$(EXE): $(COMMON_OBJS) $(RAND_OBJS) $(CRYPTO_OBJS) $(JENT_OBJS)
	$(CC) $(COMMON_OBJS) $(RAND_OBJS) $(CRYPTO_OBJS) $(JENT_OBJS) $(DEPS) -o $(EXE)

$(BIN_DIR)/%.o: $(COMMON_PATH)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/%.o: $(JENT_PATH)/%.c
	$(CC) $(CFLAGS) $(JENT_FLAGS) -c $< -o $@

$(BIN_DIR)/%.o: $(CRYPTO_PATH)/%.c
	$(CC) $(CFLAGS) $(CRYPTO_FLAGS) -c $< -o $@

$(BIN_DIR)/%.o: $(RAND_PATH)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(COMMON_OBJS) $(RAND_OBJS) $(CRYPTO_OBJS) $(JENT_OBJS)