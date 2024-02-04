DIR_BIN := ./bin

CC ?= gcc
CFLAGS := -w -I.

dir_common := ./common
srcs_common := $(dir_common)/exceptions.c
objs_common := $(DIR_BIN)/exceptions.o

dir_jent := ./jitterentropy
srcs_jent := $(dir_jent)/jitterentropy-base.c \
	   		 $(dir_jent)/jitterentropy-gcd.c \
	   		 $(dir_jent)/jitterentropy-health.c \
	   		 $(dir_jent)/jitterentropy-noise.c \
	   		 $(dir_jent)/jitterentropy-sha3.c \
	   		 $(dir_jent)/jitterentropy-timer.c
# Jitternentropy modules compiled with optimizations off
objs_jent := $(addprefix $(DIR_BIN)/, $(notdir $(srcs_jent:.c=.o)))
flags_jent := -O0

dir_crypto := ./crypto
srcs_crypto := $(dir_crypto)/aes.c \
			   $(dir_crypto)/crc.c
objs_crypto := $(addprefix $(DIR_BIN)/, $(notdir $(srcs_crypto:.c=.o)))
# Compile with optimizations enabled
flags_crypto := -msse2 -msse -march=native -maes -O3

# Crypto libraries
DEPS := -L. -lssl -lcrypto -lbcrypt

dir_rand := ./rand
srcs_rand := $(dir_rand)/rdrand.c \
			 $(dir_rand)/rngw32.c \
			 $(dir_rand)/trivium.c \
			 $(dir_rand)/random.c
objs_rand := $(addprefix $(DIR_BIN)/, $(notdir $(srcs_rand:.c=.o)))

EXE := $(DIR_BIN)/xrand

.PHONY: all

all: $(EXE) clean

$(EXE): $(objs_common) $(objs_rand) $(objs_crypto) $(objs_jent)
	$(CC) $(objs_common) $(objs_rand) $(objs_crypto) $(objs_jent) $(DEPS) -o $(EXE)

$(DIR_BIN)/%.o: $(dir_common)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(DIR_BIN)/%.o: $(dir_jent)/%.c
	$(CC) $(CFLAGS) $(flags_jent) -c $< -o $@

$(DIR_BIN)/%.o: $(dir_crypto)/%.c
	$(CC) $(CFLAGS) $(flags_crypto) -c $< -o $@

$(DIR_BIN)/%.o: $(dir_rand)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(DIR_BIN)/*.o
