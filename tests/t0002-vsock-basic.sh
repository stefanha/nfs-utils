#!/bin/bash
#
# t0002-vsock-basic.sh -- test basic NFSv4 over AF_VSOCK functionality
#
# Copyright (C) 2017  Red Hat, Stefan Hajnoczi <stefanha@redhat.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 0211-1301 USA
#

. ./test-lib.sh

check_root

test_exportfs() {
	client_addr="$1"
	export_spec="$client_addr:$(realpath .)"

	echo "TEST: $client_addr"

	"$srcdir/../utils/exportfs/exportfs" "$export_spec"
	if [ $? -ne 0 ]; then
		echo "FAIL: exportfs failed"
		exit 1
	fi

	expected_etab="$(realpath .)	$client_addr("
	grep --fixed-strings -q "$expected_etab" /var/lib/nfs/etab
	if [ $? -ne 0 ]; then
		echo "FAIL: etab doesn't contain entry"
		exit 1
	fi

	"$srcdir/../utils/exportfs/exportfs" -u "$export_spec"
	if [ $? -ne 0 ]; then
		echo "FAIL: exportfs -u failed"
		exit 1
	fi
}

test_exportfs "vsock:3"
test_exportfs "vsock:*"
