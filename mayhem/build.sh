#!/usr/bin/env bash
#
# sqlean/mayhem/build.sh — build 3 libFuzzer targets over sqlean's own C API,
# plus a NORMAL-flags build of the same 3 extensions + a `sqlite3` CLI for
# mayhem/test.sh (the project's real `test/*.sql` known-answer suites).
#
# sqlean (https://github.com/nalgeon/sqlean) is a collection of SQLite
# extensions written in C, bundling PCRE2 and a copy of SQLite itself. Of its
# ~12 extensions we picked 3 that parse untrusted bytes and harness them
# directly at the C API (SPEC's preferred style — most coverage per exec):
#
#   fuzz_regexp — regexp_compile()+bounded pcre2_match() over the bundled
#                 PCRE2 (src/regexp/regexp.c). Untrusted PATTERN + subject.
#   fuzz_fuzzy  — the phonetic/distance algorithms (src/fuzzy/*.c) fed
#                 untrusted strings directly (damerau_levenshtein, hamming,
#                 jaro(_winkler), levenshtein, optimal_string_alignment,
#                 edit_distance, caverphone, soundex, refined_soundex,
#                 phonetic_hash, transliterate, script_code).
#   fuzz_vsv    — the CSV/"variably separated values" virtual table
#                 (src/vsv/extension.c), driven through a REAL SQLite
#                 (statically-linked amalgamation, sanitized) with a FIXED
#                 CREATE VIRTUAL TABLE + SELECT * — only the `data=` CSV
#                 payload is fuzzer-controlled. `:memory:` only, never
#                 `filename=` — no filesystem writes (SPEC §6.2 item 13).
#
# NOT fuzzed: `fileio` (does real file I/O by design — explicitly out of
# scope per the integration brief), `crypto` (needs an extra external
# download, xxhash.h, for no incremental parser coverage), and the rest
# (text/math/stats/time/unicode/uuid/ipaddr/define) to keep this port
# focused on the highest-value untrusted-input surface, per the brief's
# "pick 2-4 extensions" guidance.
#
# HANG GUARD (SPEC §6b): PCRE2 match/depth limits are set explicitly in
# mayhem/fuzz_regexp.c (upstream's own regexp_like()/regexp_extract() call
# pcre2_match() with NO limit, which can hang on catastrophic backtracking —
# see that file's header comment). No other target has a hang precondition:
# the fuzzy algorithms are bounded string-length loops, and vsv's CSV reader
# only ever consumes the input once per row (bounded by input size), so an
# explicit row-count cap in the harness is defense-in-depth, not a hang fix.
#
# TWO REAL BUGS FOUND during integration (crashes, left fuzzable — see
# mayhem/fuzz_fuzzy/known-findings/): a signed-shift overflow in
# src/fuzzy/translit.c's utf8Read() on malformed UTF-8, and a heap-buffer-
# overflow read in src/fuzzy/jarowin.c's jaro_winkler() common-prefix scan
# (reachable with plain ASCII input, e.g. jaro_winkler('a','a')).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

# ── Pin + cache the SQLite amalgamation (air-gapped re-run — SPEC §6.5) ────
# Only fuzz_vsv needs a real SQLite (statically linked so it's instrumented
# by $SANITIZER_FLAGS too); the amalgamation is also reused for the NORMAL-
# flags `dist/sqlite3` CLI that mayhem/test.sh drives. Cached under
# /opt/toolchains (fixed, $HOME-independent path — SPEC §6.2 item 8): the
# first (online) build downloads+verifies it once; every later build.sh
# invocation, including the offline PATCH re-run, finds it already there and
# never touches the network.
SQLITE_VERSION=3450300
SQLITE_SHA256=ea170e73e447703e8359308ca2e4366a3ae0c4304a8665896f068c736781c651
SQLITE_CACHE=/opt/toolchains/sqlite-src
AMAL="$SQLITE_CACHE/sqlite-amalgamation-$SQLITE_VERSION"
if [ ! -f "$AMAL/sqlite3.c" ]; then
  echo "=== fetching SQLite amalgamation $SQLITE_VERSION (first build only; cached for offline re-runs) ==="
  mkdir -p "$SQLITE_CACHE"
  tmpzip="$(mktemp)"
  curl -fsSL "https://www.sqlite.org/2024/sqlite-amalgamation-$SQLITE_VERSION.zip" -o "$tmpzip"
  echo "$SQLITE_SHA256  $tmpzip" | sha256sum -c -
  unzip -q -o "$tmpzip" -d "$SQLITE_CACHE"
  rm -f "$tmpzip"
else
  echo "=== SQLite amalgamation cache hit: $AMAL ==="
fi

mkdir -p "$SRC/mayhem-build"

# ══════════════════════════════════════════════════════════════════════════
# 1) FUZZ HARNESSES — sanitized + DWARF3, one Mayhem target each, plus a
#    standalone (non-fuzzer) reproducer per target.
# ══════════════════════════════════════════════════════════════════════════

PCRE2_SRCS=()
for f in "$SRC"/src/regexp/pcre2/*.c; do
  case "$f" in *pcre2_fuzzsupport.c) continue ;; esac   # defines its own LLVMFuzzerTestOneInput
  PCRE2_SRCS+=("$f")
done

echo "=== building /mayhem/fuzz_regexp (regexp_compile + bounded pcre2_match) ==="
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    -include "$SRC/src/regexp/constants.h" -I"$SRC/src" \
    "$SRC/mayhem/fuzz_regexp.c" "$SRC/src/regexp/regexp.c" "${PCRE2_SRCS[@]}" \
    -o /mayhem/fuzz_regexp
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" \
    -include "$SRC/src/regexp/constants.h" -I"$SRC/src" \
    "$SRC/mayhem/fuzz_regexp.c" "$SRC/src/regexp/regexp.c" "${PCRE2_SRCS[@]}" \
    -o /mayhem/fuzz_regexp-standalone

echo "=== building /mayhem/fuzz_fuzzy (phonetic/distance algorithms) ==="
# extension.c is the SQLite-facing wrapper (needs sqlite3ext.h) — the fuzz
# harness calls the underlying algorithms directly and doesn't need it.
FUZZY_SRCS=()
for f in "$SRC"/src/fuzzy/*.c; do
  case "$f" in *fuzzy/extension.c) continue ;; esac
  FUZZY_SRCS+=("$f")
done
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    -I"$SRC/src" \
    "$SRC/mayhem/fuzz_fuzzy.c" "${FUZZY_SRCS[@]}" \
    -o /mayhem/fuzz_fuzzy
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" \
    -I"$SRC/src" \
    "$SRC/mayhem/fuzz_fuzzy.c" "${FUZZY_SRCS[@]}" \
    -o /mayhem/fuzz_fuzzy-standalone

echo "=== building /mayhem/fuzz_vsv (CSV vtab, driven through a sanitized in-memory SQLite) ==="
# Compile the amalgamation once (sanitized) and reuse the .o for both links.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -DSQLITE_CORE -I"$AMAL" -w \
    -c "$AMAL/sqlite3.c" -o "$SRC/mayhem-build/sqlite3-sanitized.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -DSQLITE_CORE -I"$SRC/src" -I"$AMAL" \
    "$SRC/mayhem/fuzz_vsv.c" "$SRC/src/vsv/extension.c" "$SRC/mayhem-build/sqlite3-sanitized.o" \
    -o /mayhem/fuzz_vsv -lm -ldl -lpthread
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" -DSQLITE_CORE -I"$SRC/src" -I"$AMAL" \
    "$SRC/mayhem/fuzz_vsv.c" "$SRC/src/vsv/extension.c" "$SRC/mayhem-build/sqlite3-sanitized.o" \
    -o /mayhem/fuzz_vsv-standalone -lm -ldl -lpthread

# ══════════════════════════════════════════════════════════════════════════
# 2) TEST-ORACLE BUILD — the project's NORMAL flags (no sanitizer): a
#    `sqlite3` CLI (from the same amalgamation, not the sanitized objects
#    above) plus the 3 extensions as loadable .so's, exactly like upstream's
#    own `make compile-linux` + `make test` recipe. mayhem/test.sh only RUNS
#    these; it never compiles.
# ══════════════════════════════════════════════════════════════════════════
echo "=== building dist/sqlite3 (CLI, normal flags) + regexp/fuzzy/vsv .so (for test.sh) ==="
mkdir -p "$SRC/dist"
$CC -O2 -w -I"$AMAL" -c "$AMAL/sqlite3.c" -o "$SRC/mayhem-build/sqlite3-plain.o"
$CC -O2 -w -I"$AMAL" -c "$AMAL/shell.c" -o "$SRC/mayhem-build/shell-plain.o"
$CC "$SRC/mayhem-build/sqlite3-plain.o" "$SRC/mayhem-build/shell-plain.o" \
    -o "$SRC/dist/sqlite3" -ldl -lpthread -lm

$CC -O2 -fPIC -shared -I"$SRC/src" -I"$AMAL" \
    -include "$SRC/src/regexp/constants.h" \
    "$SRC/src/sqlite3-regexp.c" "$SRC"/src/regexp/*.c "${PCRE2_SRCS[@]}" \
    -o "$SRC/dist/regexp.so"
$CC -O2 -fPIC -shared -I"$SRC/src" -I"$AMAL" \
    "$SRC/src/sqlite3-fuzzy.c" "$SRC"/src/fuzzy/*.c \
    -o "$SRC/dist/fuzzy.so"
$CC -O2 -fPIC -shared -I"$SRC/src" -I"$AMAL" \
    "$SRC/src/sqlite3-vsv.c" "$SRC"/src/vsv/*.c \
    -o "$SRC/dist/vsv.so" -lm

echo "build.sh complete:"
ls -la /mayhem/fuzz_regexp /mayhem/fuzz_regexp-standalone \
       /mayhem/fuzz_fuzzy /mayhem/fuzz_fuzzy-standalone \
       /mayhem/fuzz_vsv /mayhem/fuzz_vsv-standalone \
       "$SRC/dist/sqlite3" "$SRC/dist/regexp.so" "$SRC/dist/fuzzy.so" "$SRC/dist/vsv.so"
