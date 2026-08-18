# finding: signed-integer-overflow in `utf8Read()` (src/fuzzy/translit.c)

**Reproducer:** `utf8read-shift-overflow.bin` (13 bytes: `f5 bf bf bf bf bf bf bf bf bf bf bf bf`
— one UTF-8 "lead" byte `>= 0xC0` followed by a run of `10xxxxxx` continuation bytes).

**Target:** `mayhem/fuzz_fuzzy` (`/mayhem/fuzz_fuzzy-standalone <reproducer>` to replay).

**Cause.** `utf8Read()` in `src/fuzzy/translit.c` (line ~40) decodes a UTF-8 code point with:

```c
c = translit_utf8_lookup[c - 0xc0];
while (i < n && (z[i] & 0xc0) == 0x80) {
    c = (c << 6) + (0x3f & z[i++]);
}
```

The loop only stops on running out of input (`i < n`) or hitting a non-continuation byte — it never
stops after the number of continuation bytes implied by the lead byte (1/2/3 for a well-formed 2/3/4
-byte UTF-8 sequence). Fed a lead byte followed by many raw `0x80..0xBF` continuation bytes (not a
valid UTF-8 sequence, but nothing rejects it here), `c` is left-shifted by 6 repeatedly with no upper
bound, until the shift overflows `int` — undefined behavior (UBSan aborts the process; on a build
without UBSan this is a silent, well-defined-on-two's-complement wraparound into a bogus code point,
not a memory-safety bug by itself, but the resulting `c` then indexes/compares against the
`translit[]` table elsewhere in the same file with an attacker-influenced, wrapped-around value).

**Impact.** Reachable from real, un-gated sqlean SQL entry points — `fuzzy_translit(x)` /
`translit(x)` and `fuzzy_script(x)` / `script_code(x)` in `src/sqlite3-fuzzy.c` both pass raw,
un-validated bytes straight into `transliterate()` / `script_code()`, which call `utf8Read()` with no
ASCII/UTF-8-well-formedness gate (unlike `fuzzy_damlev` et al., which the wrapper does gate via
`is_ascii()` — see `mayhem/fuzz_fuzzy.c`'s header comment). So any caller of `select
translit(x)` / `select script_code(x)` with attacker-controlled `x` can hit this. With
`-fsanitize=undefined -fno-sanitize-recover=all` (this repo's fuzz build) it's a hard abort — a
malformed-UTF-8 denial-of-service against any query that runs one of these functions over untrusted
text. A production (non-UBSan) build "only" gets a wrapped `int`, which is not itself a crash, but a
wrapped/garbage code point index degrades output correctness in a way `is_ascii()`-style gating
elsewhere in this codebase suggests the authors did not intend.

**One-line upstream fix.** Bound the loop by the number of continuation bytes implied by the lead
byte class (2/3/4-byte forms take 1/2/3 continuation bytes respectively — RFC 3629), e.g. track an
explicit remaining-continuation-bytes counter derived from `translit_utf8_lookup`'s class instead of
looping until a non-continuation byte or EOF.

**Not guarded in the harness.** This is a real crash/UB finding, not a hang — per the integration
brief, crashes are left fuzzable (only hang *preconditions* get narrowly guarded). `fuzz_fuzzy.c`
does NOT special-case this input.

---

# finding: heap-buffer-overflow READ in `jaro_winkler()` (src/fuzzy/jarowin.c:127)

**Reproducer:** `jarowin-prefix-oob-read.bin` — 3 bytes `"a\na"` (harness splits on `\n` into
str1="a", str2="a"; equivalently: `select fuzzy_jarowin('a','a');` / `select jaro_winkler('a','a');`
— this is a REAL, fully ASCII, no-gate-needed input; it does not depend on bypassing any validation).

**Target:** `mayhem/fuzz_fuzzy` (`/mayhem/fuzz_fuzzy-standalone <reproducer>` to replay).

**Cause.** `jaro_winkler()`'s common-prefix scan:

```c
int prefix_length = 0;
if (strlen(str1) != 0 && strlen(str2) != 0) {
    while (prefix_length < 3 && EQ(*str1++, *str2++)) {
        prefix_length++;
    }
}
```

compares raw bytes without ever checking for the NUL terminator. The two strings' terminating `'\0'`
bytes compare equal to each other just like any other byte, so the loop treats "both strings ended"
as "one more matching character" and keeps advancing both pointers. For `str1=str2="a"` (each a
tightly-sized 2-byte allocation: `'a','\0'`):

- iteration 1: compares index 0 (`'a'==‘a'`) → match, pointers now at index 1 (the NUL byte, still
  in-bounds).
- iteration 2 (`prefix_length`=1 < 3): compares index 1 (`'\0'=='\0'`) → "match", pointers now at
  index 2 — **one past the allocation**.
- iteration 3 (`prefix_length`=2 < 3): reads index 2 on both strings — **out-of-bounds read**
  (confirmed by ASan: "0 bytes to the right of a 2-byte region").

Any pair of equal (or NUL-terminator-aligned) strings shorter than 3 characters — `"a","a"`,
`"ab","ab"`, `"", ...` is safe only because of the explicit `strlen()!=0` guard — hits this.

**Impact.** Reachable with ordinary ASCII input through the real, intended SQL entry points
`fuzzy_jarowin(a,b)` / `jaro_winkler(a,b)` (`src/sqlite3-fuzzy.c` → `src/fuzzy/extension.c`'s
`fuzzy_jarowin`), which only checks `is_ascii()` — not length — before calling in. So `select
jaro_winkler('a','a')` crashes a production sqlean build compiled with ASan, and reads adjacent
heap memory (potentially disclosing it into the returned score's computation, though the current
code only uses the byte for an equality test) on a build without ASan. This is the strongest of the
three findings from this integration: no non-ASCII bytes, no internal-only function, no
precondition violation — just two short equal strings passed to a documented, exported SQL function.

**One-line upstream fix.** Bound the loop by the shorter string's actual length too, e.g.
`while (prefix_length < 3 && *str1 && *str2 && *str1++ == *str2++) prefix_length++;` (stop as soon as
either string's NUL terminator is reached, before dereferencing past it).

**Not guarded in the harness.** This is a real crash finding, not a hang — left fuzzable as-is.
