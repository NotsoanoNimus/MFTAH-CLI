# Makefile for the MFTAH CLI.
#
# Zack Puhl <zack@crows.dev>
# 2024-10-17
# 
# Copyright (C) 2024 Zack Puhl
# 
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, version 3.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along with
# this program. If not, see https://www.gnu.org/licenses/.
#
#

SUPPARCHS		:= x86_64 #aarch64 riscv64 loongarch64 ia64 mips64el

# Must be set to one of the members from SUPPARCHS.
ARCH			= x86_64

ifeq ($(filter $(ARCH),$(SUPPARCHS)),)
$(error '$(ARCH)' is not a supported architecture for this program.)
endif

INCS_DIR		= src/include
SRC_DIR			= src
BUILD_DIR		= build

LIB_PTHREAD		= -lpthread
LIB_MFTAH		= -lmftah

LIBMFTAH_STATIC	= /usr/local/lib/libmftah.a

LIBS			= $(LIB_PTHREAD) $(LIB_MFTAH)
LIBS_STATIC		= $(LIB_PTHREAD)

OPTIM			= -O3
CFLAGS			= -target $(ARCH) -Wall -I$(INCS_DIR) $(OPTIM) \
					-DMFTAH_ARCH=$(ARCH) -DMFTAH_RELEASE_DATE=$(shell printf "0x`date +%04Y``date +%02m``date +%02d`")
LDFLAGS			= -target $(ARCH)

SRCS_MFTAH		= $(shell find $(SRC_DIR) -maxdepth 1 -type f -name "*.c")
MFTAH_OBJS		= $(patsubst %.c,%.o,$(SRCS_MFTAH))

OBJS			= $(MFTAH_OBJS)

TARGET			= $(BUILD_DIR)/mftahcrypt
TARGET_STATIC	= $(BUILD_DIR)/mftahcrypt-static


.PHONY: default
.PHONY: clean
.PHONY: clean-objs
.PHONY: debug
.PHONY: all

default: all

clean:
	-rm $(TARGET)* &>/dev/null
	-rm $(OBJS) &>/dev/null	

clean-objs:
	-rm $(OBJS) &>/dev/null

# We can assume a 'clean' should be run on all .o files
#   after the build completes. This is because compilation
#   of the EFI file is rather expedient anyway, and it
#   helps not to mix up release and debug build artifacts.
debug: CFLAGS += -DMFTAHCRYPT_DEBUG=1
debug: $(TARGET) clean-objs

static: $(TARGET_STATIC) clean-objs

static_debug: CFLAGS += -DMFTAHCRYPT_DEBUG=1
static_debug: $(TARGET_STATIC) clean-objs

all: $(TARGET) $(TARGET_STATIC)

%.o: %.c
	clang $(CFLAGS) -c -o $@ $<

$(BUILD_DIR):
	-@mkdir -p $(BUILD_DIR)


$(TARGET): $(BUILD_DIR) $(OBJS)
	clang $(LDFLAGS) $(LIBS) -o $(TARGET) $(OBJS)

$(TARGET_STATIC): $(BUILD_DIR) $(OBJS) $(LIBMFTAH_STATIC)
	clang $(LDFLAGS) $(LIBS_STATIC) -o $(TARGET_STATIC) $(OBJS) $(LIBMFTAH_STATIC)


install: $(TARGET)
	@chmod 755 $(TARGET)
	@cp $(TARGET) /usr/local/bin/mftahcrypt
	@echo -e "\n\n=== MFTAHCRYPT installed ===\n"

install_static: $(TARGET_STATIC)
	@chmod 755 $(TARGET_STATIC)
	@cp $(TARGET_STATIC) /usr/local/bin/mftahcrypt
	@echo -e "\n\n=== MFTAHCRYPT (static) installed ===\n"
