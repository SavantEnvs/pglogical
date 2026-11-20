#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# PostgreSQL (built once in the Dockerfile from the pinned release; see mayhem/Dockerfile).
PG=/opt/toolchains/deps/postgresql-17.12
PG_CONFIG="$PG/bin/pg_config"
OUT="$SRC/mayhem/out"
# libpq linked statically into pglogical.so, so nothing is loaded from /opt/toolchains at run time.
PGXS_ARGS=(PG_CONFIG="$PG_CONFIG" CC="$CC" libpq="$PG/lib/libpq.a $PG/lib/libpgcommon_shlib.a $PG/lib/libpgport_shlib.a")

# stage_tree <dir>: a relocated PostgreSQL install (bin/ lib/ share/) holding the pglogical
# modules just built. PostgreSQL finds share/ and lib/ relative to its executable, so a binary in
# <dir>/bin uses this tree; the extension is never installed into /opt/toolchains.
stage_tree() {
  local d="$1"
  rm -rf "$d"; mkdir -p "$d/bin" "$d/lib"
  cp "$PG/bin/postgres" "$PG/bin/initdb" "$d/bin/"
  cp -r "$PG/share" "$d/share"
  cp "$PG"/lib/*.so "$PG/lib/libpq.so.5" "$d/lib/"
  cp pglogical.so pglogical_output.so "$d/lib/"
  cp pglogical.control pglogical--*.sql "$d/share/extension/"
  chmod -R u+w "$d"
  # template data directory (SQL_ASCII, C locale; bootstrap superuser `fuzz`)
  "$d/bin/initdb" -D "$d/data-template" -U fuzz -E SQL_ASCII --locale=C -A trust --no-sync --wal-segsize=1 >/dev/null
  # readable by whichever uid runs the targets (they copy it and make the copy 0700 again)
  chmod -R a+rX "$d/data-template"
}

# 1) TEST build of pglogical with the project's normal flags (PGXS defaults), staged for test.sh.
make -s "${PGXS_ARGS[@]}" clean
make -s -j"$MAYHEM_JOBS" "${PGXS_ARGS[@]}" COPT="$COVERAGE_FLAGS" pglogical.so pglogical_output.so pglogical.control
stage_tree "$OUT/test"

# 2) FUZZ build: pglogical with ASan+UBSan, SanCov and DWARF 3. Its objects are linked INTO each
#    harness binary (libpglogical_fuzz.a), so every instrumented line is in the one fuzzed module;
#    the staged pglogical.so is only a forwarder (mayhem/harness/pglogical_stub.c) that PostgreSQL
#    dlopens by name for the SQL functions and the output plugin, and pglogical_output.so (itself
#    a forwarder upstream) is built plain.
make -s "${PGXS_ARGS[@]}" clean
# CFLAGS_SL_MODULE= drops PGXS's -fvisibility=hidden: the forwarder finds pglogical's entry points
# in the harness binary's dynamic symbol table (--export-dynamic), which hidden symbols never enter.
make -s -j"$MAYHEM_JOBS" "${PGXS_ARGS[@]}" CFLAGS_SL_MODULE= \
  COPT="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link" \
  pglogical.so
mkdir -p "$OUT"
rm -f "$OUT/libpglogical_fuzz.a"
mapfile -t PGL_OBJS < <(ls ./*.o ./compat*/pglogical_compat.o | grep -v -e '/pglogical_output\.o$' -e '/pglogical_create_subscriber\.o$')
ar rcs "$OUT/libpglogical_fuzz.a" "${PGL_OBJS[@]}"
grep -ho 'PG_FUNCTION_INFO_V1([A-Za-z0-9_]*)' ./*.c ./compat*/*.c | sort -u \
  | sed 's/PG_FUNCTION_INFO_V1(\(.*\))/FWD(\1)/' > "$OUT/pgl_stub_funcs.h"
make -s "${PGXS_ARGS[@]}" clean
make -s -j"$MAYHEM_JOBS" "${PGXS_ARGS[@]}" COPT="$DEBUG_FLAGS" pglogical_output.so pglogical.control
# -Bsymbolic: inside the forwarder, its own names mean its own functions (the recursion guard).
$CC -fPIC -shared -Wl,-Bsymbolic $DEBUG_FLAGS -I"$($PG_CONFIG --includedir-server)" -I"$OUT" \
  "$SRC/mayhem/harness/pglogical_stub.c" -o pglogical.so
stage_tree "$OUT/fuzz"
make -s "${PGXS_ARGS[@]}" clean

# 3) Harnesses: the PostgreSQL backend (everything `postgres` links but main.c) + pgl_fuzz.c, one
#    binary per mode, each also as a -standalone reproducer.
# pglogical's own headers (and its compat layer, libpq) for the apply-protocol mode
CFL=(-I"$($PG_CONFIG --includedir-server)" -I"$($PG_CONFIG --includedir)" -I"$SRC" -I"$SRC/compat17"
     $SANITIZER_FLAGS $DEBUG_FLAGS)
# The backend comes FIRST and --allow-multiple-definition keeps its definition of a name both
# define (MySubscription): that is how the dynamic linker binds pglogical.so in a real server
# (the postgres executable's symbol wins), so pglogical behaves as it does there.
# libpq: the staged (uninstrumented) libpq.so.5, found next to the binary at run time.
LNK=(-Wl,--export-dynamic -Wl,--allow-multiple-definition
     -Wl,--whole-archive "$PG/lib/libpgbackend.a" "$OUT/libpglogical_fuzz.a" -Wl,--no-whole-archive
     -L"$OUT/fuzz/lib" -l:libpq.so.5 -Wl,-rpath,'$ORIGIN/../lib'
     "$PG/lib/libpgport_srv.a" "$PG/lib/libpgcommon_srv.a" -lm -ldl -lpthread -lrt)
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
for t in output_params:PGL_MODE_OUTPUT sql_functions:PGL_MODE_FUNCS apply_proto:PGL_MODE_APPLY; do
  name="fuzz_${t%%:*}"; mode="${t#*:}"
  $CC "${CFL[@]}" -D"$mode" -DPGL_FUZZ_ROOT="\"$OUT/fuzz\"" -fsanitize=fuzzer-no-link -c "$SRC/mayhem/harness/pgl_fuzz.c" -o "$OUT/$name.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" "$OUT/lsan_off.o" "${LNK[@]}" \
    -o "$OUT/fuzz/bin/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/$name.o" "$OUT/standalone_main.o" "$OUT/lsan_off.o" "${LNK[@]}" \
    -o "$OUT/fuzz/bin/$name-standalone"
done
