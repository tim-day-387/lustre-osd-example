# SPDX-License-Identifier: GPL-2.0

KERNEL_VERSION="$(shell uname -r)"
KERNEL_DIR="/lib/modules/${KERNEL_VERSION}/build"

BUILD_DIR="$(PWD)/build"
LUSTRE_DIR="$(PWD)/../lustre-release/"

CFLAGS="-include $(PWD)/config.h \
	-include ${LUSTRE_DIR}/config.h \
	-I${LUSTRE_DIR}/lnet/include/ \
	-I${LUSTRE_DIR}/libcfs/include/ \
	-I${LUSTRE_DIR}/lustre/include/ \
	-I${LUSTRE_DIR}/libcfs/include/libcfs/ \
	-I${LUSTRE_DIR}/lnet/include/uapi/ \
	-I${LUSTRE_DIR}/lustre/include/uapi/ \
	-Wno-format-truncation -Wno-stringop-truncation \
	-Wno-stringop-overflow -g -O2 -Wall -Werror"

SYMS="${LUSTRE_DIR}/Module.symvers"

all:
	rm -rf build/
	cp -r src/ build/
	make -C $(KERNEL_DIR) CC=$(CC) KCFLAGS=$(CFLAGS) KBUILD_EXTRA_SYMBOLS=$(SYMS) M=$(BUILD_DIR)

clean:
	rm -rf build/
