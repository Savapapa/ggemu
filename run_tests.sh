#!/bin/sh
# GGEmu protocol self-tests (host build, gcc/clang)
set -e
cd "$(dirname "$0")"
CC=${CC:-gcc}
echo "== building =="
$CC -O2 -Wall -Wextra -o /tmp/ggemu_test_json   test_json.c  ../proto/gg_json.c
$CC -O2 -Wall -Wextra -o /tmp/ggemu_test_proto  test_proto.c ../proto/gg_proto.c ../proto/gg_json.c ../proto/gg_cmds.c
$CC -O2 -Wall -w -pthread       -o /tmp/ggemu_sim_session sim_session.c ../proto/gg_proto.c ../proto/gg_json.c ../proto/gg_cmds.c
echo "== json composer (byte-exact vs live-driver fixtures) =="
/tmp/ggemu_test_json
echo "== wire protocol / dispatcher =="
/tmp/ggemu_test_proto
echo "== end-to-end KM<->UM session =="
timeout 15 /tmp/ggemu_sim_session
echo "== ALL OK =="
