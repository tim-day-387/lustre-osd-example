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

	insmod build/osd_mem.ko || error "load_module failed"
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

	insmod build/osd_mem.ko || error "load_module failed"
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

	insmod build/osd_mem.ko || error "load_module failed"

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

	insmod build/osd_mem.ko || error "load_module failed"
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

	insmod build/osd_mem.ko || error "load_module failed"
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

	insmod build/osd_mem.ko || error "load_module failed"
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

	insmod build/osd_mem.ko || error "load_module failed"
	load_module kunit/llog_test || error "load_module failed"

	# Grab ENV variables for OSD mem
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

	insmod build/osd_mem.ko || error "load_module failed"

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

	insmod build/osd_mem.ko || error "load_module failed"

	# Setup servers
	export MEM_MDS="1"
	export MEM_OSS="1"
	formatall
	setupall server_only
	$LCTL set_param mdt.*.identity_upcall=NONE
	mountcli

	# Run sanity.sh tests
	export do_setup="false"
	unset ONLY
	unset ONLY_60

	# 0f, 4 - Fail; some attrs are likely not implemented correctly
	# 17o - Crash; on cleanup, crash on osp_sync_thread(), with ASSERTION(count < 10)
	# 17g - Fail; started failing with too long filename?
	# 24v - Fail; issue listing large directory?
	# 24w - Kernel error; stack trace on __alloc_pages()
	# 24A - Fail; we don't treat .. specially?
	# 27n, 27o, 27oo, 27p, 27q, 27r, 27v - Test error; no label for mds?
	# 27u - Fail; this runs too slow!
	export EXCEPT="0f 4 17o 17g 24v 24w 24A 27n 27o 27oo 27p 27q 27r 27v"
	export EXCEPT="$EXCEPT 27u"

	# Skip everything else
	export STOP_AT="27wa"
	export EXCEPT="$EXCEPT 211"

	# Hacks to make script run correctly
	export FSTYPE="zfs"
	export mds1_FSTYPE="zfs"
	export ost1_FSTYPE="zfs"
	export ost2_FSTYPE="zfs"
	export RUNAS_ID="1000"

	# Run the script!
	bash sanity.sh

	# Logs
	show_osd_env

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
		llog) om_llog;;
		list) om_list;;
		*) om_list;;
	esac
done
