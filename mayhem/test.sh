#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# pglogical's own regression suite (`make installcheck`) needs a running postmaster pair and
# streaming replication; this runs pglogical in a single-user backend instead (no postmaster) and
# checks known answers: the JSON change stream the pglogical_output plugin decodes for fixed DML,
# startup-parameter validation, and the catalog/SQL functions. The backend and the pglogical
# modules (normal flags) are the tree mayhem/build.sh staged in mayhem/out/test.
T="$SRC/mayhem/out/test"
[ -x "$T/bin/postgres" ] && [ -f "$T/lib/pglogical.so" ] && [ -d "$T/data-template" ] \
  || { echo "test.sh: $T missing — run mayhem/build.sh first" >&2; emit_ctrf "pglogical-single-user" 0 1; exit 1; }
D=$(mktemp -d "${TMPDIR:-/tmp}/pgl_test.XXXXXX")
trap 'rm -rf "$D"' EXIT
mkdir -p "$D/data" && cp -r "$T/data-template/." "$D/data/"
chmod -R u+rwX,go-rwx "$D/data"
"$T/bin/postgres" --single -D "$D/data" -c shared_preload_libraries=pglogical -c wal_level=logical \
  -c output_plugin_libraries=pgoutput,test_decoding,pglogical_output -c log_min_messages=error \
  -c fsync=off postgres < "$SRC/mayhem/test.sql" > "$D/out.txt" 2>&1

passed=0; failed=0
expect() {  # expect <name> <fixed string that must appear in the backend output>
  if grep -qF -- "$2" "$D/out.txt"; then passed=$((passed+1)); echo "PASS $1"
  else failed=$((failed+1)); echo "FAIL $1: missing: $2"; fi
}
expect create_node 'create_node = "'
expect add_table 'replication_set_add_table = "t"'
expect startup_msg '"action":"S", "params": {"max_proto_version":"1","min_proto_version":"1"'
expect startup_version '"pglogical_version":"2.4.8","pglogical_version_num":"20408"'
expect startup_no_txinfo '"no_txinfo":"t"}}'
expect insert_1 '{"action":"I","relation":["public","t"],"newtuple":{"a":1,"b":"hello"}}'
expect insert_2 '{"action":"I","relation":["public","t"],"newtuple":{"a":2,"b":"world"}}'
expect update '{"action":"U","relation":["public","t"],"newtuple":{"a":2,"b":"there"}}'
expect commit '{"action":"C"}'
expect replicate_only_table_rejected 'ERROR:  invalid replication_only_table nodot'
expect gen_slot_name 'pglogical_gen_slot_name = "pgl_db_prov_sub"'
expect version 'pglogical_version = "2.4.8"'
expect row_filter_rejected 'ERROR:  syntax error at or near "FROM"'
expect repset_info_relname 'relname = "t"'
expect repset_info_atts 'att_list = "{a,b}"'
expect node_info 'node_name = "n"'
if [ "$(grep -c '"action":"I"' "$D/out.txt")" -ne 2 ]; then failed=$((failed+1)); echo "FAIL insert_count"; else passed=$((passed+1)); echo "PASS insert_count"; fi
[ "$failed" -eq 0 ] || { echo "--- backend output ---"; cat "$D/out.txt"; }
emit_ctrf "pglogical-single-user" "$passed" "$failed"
