# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := prog_kern
USER_TARGETS := prog_userspace

# LLC ?= llc
# CLANG ?= clang
# CC := gcc

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

# COMMON_OBJS := $(COMMON_DIR)/common_params.o
COMMON_OBJS += $(COMMON_DIR)/common_libbpf.o
include $(COMMON_DIR)/common.mk
