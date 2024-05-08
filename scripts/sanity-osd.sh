#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#
# Helper to more quickly debug OSDs. This was primarily
# designed to help develop the in-memory OSD - but could
# adapted to be more general.
#
# Author: Timothy Day <tday141@gmail.com>
#

#
# Validate that the OSD is correctly torn down
# and unloaded.
#
function run_osd_env_check() {
	if $(mount | grep -q "osd-mem"); then
		error "osd-mem still mounted!"
	fi

	if $(lsmod | grep -q "osd-mem"); then
		error "osd-mem still loaded!"
	fi
}

#
# Log that the OSD is loaded and setup
#
function show_osd_env() {
	# Log devices and mounts
	echo "Devices:"
	cat "$dev_path" | grep "osd-mem"
	echo "Mounts:"
	mount | grep "osd-mem"
}

#
# Run a single sanity test from this script,
# along with needed setup and cleanup
#
function run_osd_test() {
	export test_num="$1"
	export message="$2"
	export ONLY="$test_num"
	export ONLY_${test_num}="1"

	# Test setup
	load_modules

	# Run test
	run_test "$test_num" "$message"
	run_osd_env_check
}

#
# Perform needed cleanup.
# NOTE: Running this in run_osd_test() causes the script
# to exit early from some reason.
#
function run_osd_cleanup() {
	# Post-test cleanup
	osd_mark "Start cleanup"
	sleep 5
	cleanupall -f
}

#
# Print to dmesg, now with equals signs!
#
function osd_mark() {
	$LCTL mark "==================== $1 ===================="
}

#
# Test simple OBD lifecycle of OSD.
# NOTE: This test might not work with a fully functional
# OSD, since the lifecycle may be more complex.
#
function test_10() {
	local dev_path="/sys/kernel/debug/lustre/devices"

	insmod build/osd_mem.ko || true
	echo $VB_OSD_DEBUG | tee /sys/module/osd_mem/parameters/verbose_debug

	# This must be run in iteractive mode, since attach and setup
	# are stateful
	eval "$LCTL <<-EOF || error 'OBD device creation failed'
		attach osd-mem obd_name obd_uuid
		setup osd-mem
	EOF"

	echo "Devices:"
	cat "$dev_path" | tail -n 10

	$LCTL --device "obd_name" cleanup
	$LCTL --device "obd_name" detach

	dmesg | tail -n 25 | grep "Lustre: OBD:.*FAIL" &&
		error "OBD unit test failed"

	rmmod -v osd_mem ||
		error "rmmod failed (may trigger a failure in a later test)"
}

#
# Setup/teardown a single OST.
#
function test_20() {
	local dev_path="/sys/kernel/debug/lustre/devices"

	insmod build/osd_mem.ko || true
	echo $VB_OSD_DEBUG | tee /sys/module/osd_mem/parameters/verbose_debug

	# Setup servers
	formatall
	setupall server_only
	$LCTL set_param mdt.*.identity_upcall=NONE
	mountcli

	# Grab ENV variables for OSD mem
	export OSD_MEM_TGT_TYPE=${OSD_MEM_TGT_TYPE:-"OST"}
	export OSD_MEM_INDEX=${OSD_MEM_INDEX:-"2"}
	export OSD_MEM_MGS_NID=${OSD_MEM_MGS_NID:-"$(hostname -i)@tcp"}

	# Perform mount
	mkdir -p /mnt/osd-mem
	$LUSTRE/utils/mount.lustre -v /mnt/osd-mem

	# Logs
	show_osd_env

	# Perform umount
	sleep 10
	osd_mark "Start umount"
	umount /mnt/osd-mem
	run_osd_cleanup
}

#
# Setup/teardown a multiple OST. This is to ensure a single
# driver correctly differentiates between different disks.
#
function test_22() {
	local dev_path="/sys/kernel/debug/lustre/devices"

	insmod build/osd_mem.ko || true

	# OSD mem specific variables
	export MEM_OSS="1"
	export OSTCOUNT="10"

	# Setup servers
	formatall
	setupall server_only

	# Logs
	show_osd_env

	# Perform umount
	run_osd_cleanup
}

#
# Setup/teardown a single MGT.
#
function test_30() {
	local dev_path="/sys/kernel/debug/lustre/devices"

	insmod build/osd_mem.ko || true
	echo $VB_OSD_DEBUG | tee /sys/module/osd_mem/parameters/verbose_debug

	# Grab ENV variables for OSD mem
	export OSD_MEM_TGT_TYPE=${OSD_MEM_TGT_TYPE:-"MGT"}
	export OSD_MEM_INDEX=${OSD_MEM_INDEX:-"0"}
	export OSD_MEM_MGS_NID=${OSD_MEM_MGS_NID:-"$(hostname -i)@tcp"}

	# Perform mount
	mkdir -p /mnt/osd-mem
	$LUSTRE/utils/mount.lustre -v /mnt/osd-mem

	# Logs
	show_osd_env

	# Perform umount
	sleep 10
	osd_mark "Start umount"
	umount /mnt/osd-mem
	run_osd_cleanup
}

#
# Setup/teardown a combined MGT/MDT.
#
function test_32() {
	local dev_path="/sys/kernel/debug/lustre/devices"

	insmod build/osd_mem.ko || true
	echo $VB_OSD_DEBUG | tee /sys/module/osd_mem/parameters/verbose_debug

	# Grab ENV variables for OSD mem
	export OSD_MEM_TGT_TYPE=${OSD_MEM_TGT_TYPE:-"MDT"}
	export OSD_MEM_PRIMARY_MDT="1"
	export OSD_MEM_INDEX=${OSD_MEM_INDEX:-"0"}
	export OSD_MEM_MGS_NID=${OSD_MEM_MGS_NID:-"$(hostname -i)@tcp"}

	# Perform mount
	mkdir -p /mnt/osd-mem
	$LUSTRE/utils/mount.lustre -v /mnt/osd-mem

	# Logs
	show_osd_env

	# Perform umount
	sleep 10
	osd_mark "Start umount"
	umount /mnt/osd-mem
	run_osd_cleanup
}

#
# Setup/teardown a single (non-primary) MDT
#
function test_40() {
	local dev_path="/sys/kernel/debug/lustre/devices"

	insmod build/osd_mem.ko || true
	echo $VB_OSD_DEBUG | tee /sys/module/osd_mem/parameters/verbose_debug

	# Setup servers
	formatall
	setupall server_only

	# Grab ENV variables for OSD mem
	export OSD_MEM_TGT_TYPE=${OSD_MEM_TGT_TYPE:-"MDT"}
	export OSD_MEM_INDEX=${OSD_MEM_INDEX:-"1"}
	export OSD_MEM_MGS_NID=${OSD_MEM_MGS_NID:-"$(hostname -i)@tcp"}

	# Perform mount
	mkdir -p /mnt/osd-mem
	$LUSTRE/utils/mount.lustre -v /mnt/osd-mem

	# Logs
	show_osd_env

	# Perform umount
	sleep 10
	osd_mark "Start umount"
	umount /mnt/osd-mem
	run_osd_cleanup
}

#
# Setup/teardown a single MGT and run the llog regression tests.
# This exercises the osd read/write interfaces.
#
function test_50() {
	local dev_path="/sys/kernel/debug/lustre/devices"

	insmod build/osd_mem.ko || true
	load_module kunit/llog_test || error "load_module failed"

	# Grab ENV variables for OSD mem
	export FSTYPE="mem"
	export OSD_MEM_TGT_TYPE=${OSD_MEM_TGT_TYPE:-"MGT"}
	export OSD_MEM_INDEX=${OSD_MEM_INDEX:-"0"}
	export OSD_MEM_MGS_NID=${OSD_MEM_MGS_NID:-"$(hostname -i)@tcp"}

	# Perform mount
	mkdir -p /mnt/osd-mem
	$LCTL mark "Attempt OSD mount"
	$LUSTRE/utils/mount.lustre -v /mnt/osd-mem
	$LCTL mark "Finish OSD mount"

	# Get new MGS
	export MGS=$($LCTL dl | awk '/mgs/ { print $4 }')

	# Using ignore_errors will allow lctl to cleanup even if the test fails.
	$LCTL mark "Attempt llog unit tests"
	eval "$LCTL <<-EOF || RC=2
		attach llog_test llt_name llt_uuid
		ignore_errors
		setup $MGS
		--device llt_name cleanup
		--device llt_name detach
	EOF"
	$LCTL mark "Finish llog units tests"

	# Logs
	show_osd_env

	# Perform umount
	sleep 10
	osd_mark "Start umount"
	umount /mnt/osd-mem
	run_osd_cleanup
}

#
# Setup a filesystem with OSD mem MDT/MGT and run a few
# sanity.sh tests.
#
function test_60() {
	local dev_path="/sys/kernel/debug/lustre/devices"

	insmod build/osd_mem.ko || true

	# Setup servers
	export MEM_MDS="1"
	formatall
	setupall server_only
	$LCTL set_param mdt.*.identity_upcall=NONE
	mountcli

	# Run sanity.sh tests
	export do_setup="false"
	unset ONLY
	unset ONLY_60
	export ONLY="0a 0b 1 2 3 7b 9 10 14 15 16 17a 17b 17c"
	export ONLY="$ONLY 17d 17e 17f"
	export RUNAS_ID="1000"
	bash sanity.sh

	# Logs
	show_osd_env

	# Perform cleanup
	sleep 10
	run_osd_cleanup

	return 0
}

#
# Setup a filesystem with OSD mem for all servers and run a few
# sanity.sh tests.
#
function test_70() {
	local dev_path="/sys/kernel/debug/lustre/devices"

	insmod build/osd_mem.ko || true

	# Setup servers
	export FSTYPE="mem"
	export MEM_MDS="1"
	export MEM_OSS="1"
	export MDSCOUNT="4"
	export OSTCOUNT="4"
	setupall server_only
	$LCTL set_param mdt.*.identity_upcall=NONE
	mountcli

	# Run sanity.sh tests
	export do_setup="false"
	unset ONLY
	unset ONLY_60

	# 0f, 4 - Fail; some attrs are likely not implemented correctly
	# 17g - Fail; started failing with too long filename?
	# 17o - Fail; Can't restart services correctly
	# 24v - Fail; issue listing large directory?
	# 24A - Fail; we don't treat .. specially?
	# 24B - Fail; striped dirs are broken?
	# 27u - Fail; this runs too slow!
	# 27z - Test error; restarting OSS fails?
	# 27A - Test error; stripe size is equal, but script fails?
	# 27F - Fail; checkstat failed!
	# 27G - Fail; still testpool!
	# 27M - Fail; incorrect stripe count!
	# 31e - Fail; remove of open non-empty directory fails
	# 31g, 31h, 31i, 31n - Fail; nlink issues?
	# 33i - Fail; striped directory can be accessed when one MDT is down
	# 34a - Fail; truncate file that has not been opened
	# 34b - Fail; O_RDONLY doesn't work
	# 34c - Fail; O_RDRW doesn't work
	# 34d, 34e, 34f, 34g, 34h - Fail; seems like size acct'ing wrong?
	# 39o, 39p - Fail; nlink issues?
	# 52a, 52b - Fail; Append only doesn't work
	# 56c - Fail; device status isn't working?
	# 56oc, 56od, 56ra - Fail; some attr is being reported correctly?
	# 56xb, 56xc - Fail; links broken?
	# 56aa, 56ab - Fail; size/block attr wrong?
	# 56eda, 56edb - Fail; links broken?
	# 56eg - Fail; It seems like find variants are broken?
	# 60g - Fail; LFSCK doesn't work!
	# 60h - Fail; IOC_MDC_GETFILEINFO ioctl failed
	# 64i - Fail; We can't restart OSS correctly?
	# 65g - Fail; Deleting default striping troubles...
	# 65n - Fail; extended attribute woes...
	# 66 - Fail; block acct'ing still broken
	# 81b - Fail; space acct'ing? ENOSPC issues...
	# 101g - Fail; Big bulk(4/16 MiB) readahead
	# 102a, 102h, 102ha - Fail; user xattrs might not be working
	# 102k - Fail; we don't crash, but the attrs are wrong?
	# 102r, 102t - Fail; extended attribute woes...
	# 103e, 103f - Fail; ACL issues?
	# 104d - Fail; lctl dl is busted?
	# 110 - Fail; filename length checking
	# 119e, 119f, 119g, 119h - Fail; rotational checking
	# 120b - Fail; one cancel RPC occured?
	# 123e, 123h - Fail; Input/Output error
	# 124b - Crash; LDLM kunit test explodes
	# 130a, 130b, 130c, 130d, 130e, 130g - Fail; filefrag issues
	# 133c - Fail; destroy counter broken?
	# 150a - Fail; truncate issues
	# 154B, 154f - Fail; linkea? ldiskfs?
	# 154g - Fail; FID to Path issues?
	# 155, 156, 160 - Fail; Perhaps we need a working procfs?
	# 161c, 161b - Fail; Changelog issues
	# 165 - Fail; ofd access log
	# 184d, 184e - Fail; Input/Output error
	# 185 - Fail; Volatile file support
	# 187a - Fail; Data version issues
	# 205a - Fail; Changelog issues
	# 205h - Fail; extended attribute woes...
	# 208 - Fail; Exclusive open? This hangs forever?
	# 36g, 51b, 56wa - Fail; This appears to pass in isolation, but fails in a full run
	# 27oo - Fail; Can't restart services?
	# 27p, 27q - Fail; truncate isn't working...
	# 27r, 27v - Fail; -19? ENODEV? Seems like a script failure...
	# 53 - Fail; Seems to depend on lprocfs?
	# 65k - Fail; Import doesn't seem like it can come back?
	# 42e, 56wb, 56xd, 56xe, 56xf, 56ec, 59 - Fail; This appears to pass in isolation, but fails in a full run
	export EXCEPT="0f 4 17g 17o 24v 24A 24B 27oo 27p 27q 27r 27v"
	export EXCEPT="$EXCEPT 27u 27z 27A 27F"
	export EXCEPT="$EXCEPT 27G 27M 31e 31g 31h 31i 31n 33i 34a 34b"
	export EXCEPT="$EXCEPT 34c 34d 34e 34f 34g 34h 39o 39p 52a 52b"
	export EXCEPT="$EXCEPT 56c 56oc 56od 56ra 56xb 56xc 56aa 56ab"
	export EXCEPT="$EXCEPT 56eda 56edb 56eg 60g 60h 64i 65g 65n 66"
	export EXCEPT="$EXCEPT 81b 101g 102a 102h 102ha 102k 102r 102t"
	export EXCEPT="$EXCEPT 103e 103f 104d 110 119e 119g 119h 120b"
	export EXCEPT="$EXCEPT 123e 123h 124b 130a 130b 130c 130d 130e 130g"
	export EXCEPT="$EXCEPT 133c 150a 154B 154f 154g 155 156 160 161c 161b"
	export EXCEPT="$EXCEPT 165 184d 184e 185 187a 205a 205h 208 36g 51b"
	export EXCEPT="$EXCEPT 56wa 53 65k 42e 56wb 56xd 56xe 56xf 56ec 59"

	# TODO: These get automatically SKIP'ed
	# 27y - Skip; Not enough space on OST, likely acct'ing error?
	# 27Cd - Skip; ea_inode feature disabled?

	# TODO: This is the last test we've run. Need to try running the
	# remainder in the suite. Stop sooner for stability reasons.
	#
	# export STOP_AT="208"
	export STOP_AT="64a"

	# Hacks to make script run correctly
	export RUNAS_ID="1000"

	# If START_AT is set, ignore everything above!
	if [[ -n "$START_AT" ]]; then
		unset EXCEPT
		STOP_AT="$START_AT"
	fi

	# Run the script!
	bash sanity.sh

	# Logs
	show_osd_env

	# Perform cleanup
	sleep 10
	run_osd_cleanup

	return 0
}

#
# Setup a filesystem with OSD mem for all servers and run a compile
# test.
#
function test_80() {
	local dev_path="/sys/kernel/debug/lustre/devices"

	insmod build/osd_mem.ko || true

	stack_trap "run_osd_cleanup"

	# Setup servers
	export FSTYPE="mem"
	export MEM_MDS="1"
	export MEM_OSS="1"
	export MDSCOUNT="4"
	export OSTCOUNT="4"
	setupall server_only
	$LCTL set_param mdt.*.identity_upcall=NONE
	mountcli

	# Get Lustre source
	chmod 777 /mnt/lustre
	cd /mnt/lustre
	git clone git://git.whamcloud.com/fs/lustre-release.git

	# umount/mount
	sync; echo 3 > /proc/sys/vm/drop_caches
	cd /
	umount /mnt/lustre
	mountcli

	# Check for files
	cd /mnt/lustre/lustre-release
	ls

	# Configure
	cd /mnt/lustre/lustre-release
	./autogen.sh
	./configure --disable-server

	# umount/mount
	sync; echo 3 > /proc/sys/vm/drop_caches
	cd /
	umount /mnt/lustre
	mountcli

	# Check for files
	cd /mnt/lustre/lustre-release
	ls

	# Configure
	cd /mnt/lustre/lustre-release
	make -j$(nproc) -s

	# umount/mount
	sync; echo 3 > /proc/sys/vm/drop_caches
	cd /
	umount /mnt/lustre
	mountcli

	# Check for files
	cd /mnt/lustre/lustre-release
	find . -name *.ko

	# umount
	sync; echo 3 > /proc/sys/vm/drop_caches
	cd /
	umount /mnt/lustre

	# Perform cleanup
	sleep 10
	run_osd_cleanup

	return 0
}

function om_list() {
	less -F <<EOF
Usage: ${0##*/} [options]
Helper for running tests against OSD mem
	all                Run regression tests.
	obd                Setup/cleanup OBD device.
	ost_mount          Attempt a simple OST mount test.
	mgt_mount          Attempt a simple MGT mount test.
	mgt_mdt_mount      Attempt a combined MGT/MDT mount test.
	mgt_mdt_sanity     Run sanity with OSD mem MGT/MDT.
	mdt_mount          Attempt a simple MDT mount test.
	sanity             Run sanity with OSD mem MGT/MDT/OST.
	llog               Run llog unit tests.
	list               List all possible commands.
EOF
	exit
}

function om_all() {
	# Disable verbose debugging, for speed!
	export VB_OSD_DEBUG=0

	# Setup OST with filesystem
	run_osd_test 20 "single OST test"

	# Setup multiple OST with filesystem
	run_osd_test 22 "multiple OST test"

	# Setup primary MDT with filesystem
	run_osd_test 32 "osd-mem MGT/MDT mount"

	# Run llog unit tests
	run_osd_test 50 "llog unit tests"

	# Run sanity tests
	run_osd_test 70 "osd-mem sanity test"

	# Compile Lustre on Lustre!
	run_osd_test 80 "compile Lustre on Lustre"
}

function om_obd() {
	run_osd_test 10 "osd-mem OBD device"
}

function om_ost_mount() {
	export VB_OSD_DEBUG=1
	run_osd_test 20 "osd-mem OST mount"
}

function om_mgt_mount() {
	export VB_OSD_DEBUG=1
	run_osd_test 30 "osd-mem MGT mount"
}

function om_mgt_mdt_mount() {
	export VB_OSD_DEBUG=1
	run_osd_test 32 "osd-mem MGT/MDT mount"
}

function om_mdt_mount() {
	export VB_OSD_DEBUG=1
	run_osd_test 40 "osd-mem MDT mount"
}

function om_llog() {
	export VB_OSD_DEBUG=0
	run_osd_test 50 "osd-mem MGT mount and llog test"
}

function om_mgt_mdt_sanity() {
	export VB_OSD_DEBUG=0
	run_osd_test 60 "osd-mem MGT/MDT sanity test"
}

function om_sanity() {
	export VB_OSD_DEBUG=0
	run_osd_test 70 "osd-mem sanity test"
}

function om_compile() {
	export VB_OSD_DEBUG=0
	run_osd_test 80 "compile Lustre on Lustre"
}

# Run as root or with sudo
if [[ "$EUID" -ne 0 ]]; then
	echo "Please run as root or with sudo."
	exit
fi

# Init Lustre test stuff
LUSTRE=${LUSTRE:-"$(dirname "$0")/../../lustre-release/lustre"}
. "$LUSTRE/tests/test-framework.sh"
init_test_env "$@"
load_modules
init_logging

# Process options
for arg in "$@"; do
	shift
	case "$arg" in
		all) om_all;;
		obd) om_obd;;
		ost_mount) om_ost_mount;;
		mgt_mdt_mount) om_mgt_mdt_mount;;
		mgt_mount) om_mgt_mount;;
		mdt_mount) om_mdt_mount;;
		mgt_mdt_sanity) om_mgt_mdt_sanity;;
		sanity) om_sanity;;
		compile) om_compile;;
		llog) om_llog;;
		list) om_list;;
		*) om_list;;
	esac
done
