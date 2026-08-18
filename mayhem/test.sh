#!/usr/bin/env bash
#
# sqlean/mayhem/test.sh — RUN the project's own known-answer SQL suites
# (test/regexp.sql, test/fuzzy.sql, test/vsv.sql — built by mayhem/build.sh
# into dist/sqlite3 + dist/{regexp,fuzzy,vsv}.so with NORMAL flags) plus 3
# hand-written known-answer probes, one per extension, and emit a CTRF
# summary. This script only RUNS things; it never compiles.
#
# THE SABOTAGE TRAP (do not repeat pkgconf's mistake): upstream's own test
# harness (`make test`) is `$(SQLITE) < test/$(suite).sql | (! grep -Ex
# "[0-9_]+.[^1]")` — it PASSES whenever the FAILURE pattern is ABSENT from
# the output. That is exit/liveness-shaped: a `sqlite3` neutered by the
# gate's LD_PRELOAD shim (constructor `_exit(0)`s any binary not under
# /usr/bin,/bin,… — and dist/sqlite3 lives under $SRC/dist, so it qualifies)
# produces EMPTY stdout before reading a byte of stdin. Empty output also
# contains no failure-pattern line, so upstream's own check would report a
# hollow "pass" — the exact same trap `meson test`/`ctest` fell into
# (proven empirically on pkgconf: sabotage still printed 32/32 OK).
#
# So instead of "absence of failure", every check below requires POSITIVE
# evidence of real output:
#   1) each suite's PASS-line count must equal the suite's own known
#      assertion count (derived from grep -c "^select '" on the .sql file
#      itself — a plain text read via bash, which the shim can't touch) —
#      an empty/short/neutered run has fewer (usually zero) pass lines and
#      is caught by the count mismatch, not by an absence-of-failure check.
#   2) 3 direct KAT probes — one per extension — assert an EXACT computed
#      value (a regexp substring match, a Levenshtein distance number, a
#      vsv-parsed CSV field) via `grep -qxF` against dist/sqlite3's raw
#      stdout. Empty stdout cannot satisfy any of these `-qxF` checks, so a
#      neutered run fails all three, not just "looks different".
# Both together satisfy SPEC §6.3: "test.sh FAILS when the program is
# neutered" — verified by hand (build, run normal -> passes; re-run under
# the same LD_PRELOAD shim verify-repo uses -> all 3 KAT checks AND all 3
# suite counts fail, exit non-zero, CTRF reports failed>0).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

if [ ! -x "$SRC/dist/sqlite3" ]; then
  echo "FATAL: $SRC/dist/sqlite3 missing — mayhem/build.sh should have built it" >&2
  emit_ctrf "sqlean-sql" 0 1
  exit 1
fi

PASSED=0
FAILED=0

# ── 1) the project's own known-answer SQL suites ─────────────────────────
# UNCONDITIONAL: a missing .sql file, a missing .so, or empty sqlite3 output
# is counted as a FAILURE (expected>0 always, so an actual==0 mismatch below
# always fails) — never silently skipped.
run_suite() {
  local suite="$1" load="$2"
  local sqlfile="$SRC/test/$suite.sql"
  if [ ! -f "$sqlfile" ]; then
    echo "FAIL suite=$suite: $sqlfile missing" >&2
    FAILED=$((FAILED + 1))
    return
  fi
  local expected
  expected=$(grep -c "^select '" "$sqlfile")
  local out
  out="$(cd "$SRC" && ./dist/sqlite3 2>&1 <<SQL
.load dist/$load
.read $sqlfile
SQL
)"
  local actual_total actual_pass actual_fail
  actual_total=$(printf '%s\n' "$out" | grep -cE '^[0-9_]+\|[01]$' || true)
  actual_pass=$(printf '%s\n' "$out" | grep -cE '^[0-9_]+\|1$' || true)
  actual_fail=$(printf '%s\n' "$out" | grep -cE '^[0-9_]+\|0$' || true)
  echo "suite=$suite expected=$expected total=$actual_total pass=$actual_pass fail=$actual_fail"
  if [ "$actual_fail" -ne 0 ]; then
    echo "FAIL suite=$suite: $actual_fail assertion(s) evaluated false:" >&2
    printf '%s\n' "$out" | grep -E '^[0-9_]+\|0$' | sed 's/^/        /' >&2
  fi
  if [ "$expected" -eq 0 ] || [ "$actual_total" -ne "$expected" ] || [ "$actual_pass" -ne "$expected" ]; then
    echo "FAIL suite=$suite: expected $expected passing assertions, got total=$actual_total pass=$actual_pass (empty/short output means the binary did no real work — e.g. neutered)" >&2
    FAILED=$(( FAILED + (expected > 0 ? expected : 1) ))
    PASSED=$((PASSED + actual_pass))
  else
    PASSED=$((PASSED + actual_pass))
  fi
}

run_suite regexp regexp
run_suite fuzzy fuzzy
run_suite vsv vsv

# ── 2) direct KAT probes — one per extension, EXACT stdout value ─────────
# Each is unconditional: `grep -qxF` on empty/wrong stdout simply fails —
# there is no guard that could turn a missing/neutered result into a skip.
kat_check() {
  local label="$1" script="$2" expect="$3"
  local out
  out="$(cd "$SRC" && ./dist/sqlite3 2>&1 <<SQL
$script
SQL
)"
  if printf '%s\n' "$out" | grep -qxF "$expect"; then
    echo "KAT PASS: $label -> $expect"
    PASSED=$((PASSED + 1))
  else
    echo "KAT FAIL: $label — expected exact line '$expect', got:" >&2
    printf '%s\n' "$out" | sed 's/^/        /' >&2
    FAILED=$((FAILED + 1))
  fi
}

# regexp: extract the year out of a fixed sentence via the bundled PCRE2.
kat_check "regexp_substr digit match" \
  ".load dist/regexp
select regexp_substr('the year is 2021', '\\d+');" \
  "2021"

# fuzzy: Levenshtein distance between two fixed known strings is exactly 3.
kat_check "fuzzy_leven(kitten,sitting)" \
  ".load dist/fuzzy
select fuzzy_leven('kitten', 'sitting');" \
  "3"

# vsv: parse a fixed 3-row CSV payload (via data=, never filename= — no
# filesystem) and pull one field back out through the virtual table.
kat_check "vsv CSV field lookup" \
  ".load dist/vsv
create virtual table people using vsv(
    data='11,Diane,London
22,Grace,Berlin
33,Alice,Paris
',
    schema=\"create table people(id integer, name text, city text)\",
    columns=3,
    affinity=integer
);
select name from people where id = 22;" \
  "Grace"

emit_ctrf "sqlean-sql" "$PASSED" "$FAILED"
