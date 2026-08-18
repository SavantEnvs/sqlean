// mayhem/fuzz_fuzzy.c — libFuzzer harness for sqlean's `fuzzy` extension.
//
// Exercises the extension's own C API directly (src/fuzzy/fuzzy.h) — no
// SQLite dependency at all (the distance/phonetic/translit algorithms are
// pure string functions; sqlite3-fuzzy.c only wraps them as SQL functions).
// Feeds untrusted strings to:
//   - distance metrics (two strings):    damerau_levenshtein, hamming,
//                                         jaro_winkler, levenshtein,
//                                         optimal_string_alignment,
//                                         edit_distance
//   - phonetics (one string):            caverphone, soundex,
//                                         refined_soundex, phonetic_hash
//   - translit (one string + length):    transliterate, script_code
//
// Input format: split the fuzzer bytes on the first '\n' into two
// NUL-terminated strings str1/str2 (str2 empty if no '\n').
//
// ASCII GATE — matches the real reachable surface, not a mask: the SQL-layer
// wrapper (src/fuzzy/extension.c's is_ascii()) rejects non-ASCII input for
// damerau_levenshtein/hamming/jaro(_winkler)/levenshtein/
// optimal_string_alignment/soundex/refined_soundex/caverphone BEFORE ever
// calling into them — every real caller through the sqlean SQL API is
// guaranteed ASCII-only bytes for these. We discovered the hard way that
// skipping this gate finds a crash that is real (damlev.c:78/91 indexes a
// fixed-size `dict[]` table with `(unsigned)str2[col-1]` — on a platform
// where `char` is signed, a byte with the high bit set sign-extends to a
// huge unsigned index, corrupting far out of bounds) but NOT reachable
// through sqlean's actual attack surface (the is_ascii() gate always runs
// first for these functions) — see mayhem/fuzz_fuzzy/known-findings/ for the
// writeup and reproducer. Replicating the same gate here keeps the harness
// honest about what an attacker can actually deliver through SQL, exactly
// like edit_distance()'s pnMatch contract below. `edit_distance()` is exempt
// because it self-guards (returns -2 on a high-bit byte); `phonetic_hash()`/
// `transliterate()`/`script_code()` are exempt because their real callers
// (fuzzy_phonetic/fuzzy_translit/fuzzy_script) pass raw bytes un-gated by
// design (they exist to handle non-ASCII/UTF-8 input).
//
// No filesystem; no hang risk (bounded string-length algorithms, not
// backtracking searches).
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzzy/fuzzy.h"

#define MAX_LEN 4096

// Mirrors src/fuzzy/extension.c's static is_ascii() exactly.
static int is_ascii(const char* str) {
    for (int idx = 0; str[idx]; idx++) {
        if (((const unsigned char*)str)[idx] & 0x80) {
            return 0;
        }
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return 0;
    }
    if (size > 2 * MAX_LEN) {
        size = 2 * MAX_LEN;
    }

    const uint8_t* nl = memchr(data, '\n', size);
    size_t len1 = nl ? (size_t)(nl - data) : size;
    const uint8_t* data2 = nl ? nl + 1 : data + size;
    size_t len2 = nl ? (size_t)(data + size - data2) : 0;
    if (len1 > MAX_LEN) len1 = MAX_LEN;
    if (len2 > MAX_LEN) len2 = MAX_LEN;

    char* str1 = malloc(len1 + 1);
    char* str2 = malloc(len2 + 1);
    if (!str1 || !str2) {
        free(str1);
        free(str2);
        return 0;
    }
    memcpy(str1, data, len1);
    str1[len1] = '\0';
    memcpy(str2, data2, len2);
    str2[len2] = '\0';

    // Distance metrics (two strings) — real callers require ASCII on BOTH.
    if (is_ascii(str1) && is_ascii(str2)) {
        (void)damerau_levenshtein(str1, str2);
        (void)hamming(str1, str2);
        (void)jaro(str1, str2);
        (void)jaro_winkler(str1, str2);
        (void)levenshtein(str1, str2);
        (void)optimal_string_alignment(str1, str2);
    }
    // pnMatch MUST be NULL unless zA ends in '*' (see editdist.c's own
    // comment + assert) — the only real caller (src/fuzzy/extension.c's
    // fuzzy_editdist) always passes 0, so we match that exactly here.
    // (edit_distance self-guards against non-ASCII, so no gate needed.)
    (void)edit_distance(str1, str2, 0);

    // Phonetics (one string) — real callers require ASCII for these three.
    if (is_ascii(str1)) {
        char* p;
        p = caverphone(str1);
        free(p);
        p = soundex(str1);
        free(p);
        p = refined_soundex(str1);
        free(p);
    }
    // phonetic_hash takes raw bytes + explicit length by design (no gate).
    unsigned char* uh = phonetic_hash((const unsigned char*)str1, (int)len1);
    free(uh);

    // Translit (one string + explicit length — exercises multi-byte UTF-8
    // handling, since fuzzer input is not restricted to ASCII).
    unsigned char* ut = transliterate((const unsigned char*)str1, (int)len1);
    free(ut);
    (void)script_code((const unsigned char*)str1, (int)len1);

    free(str1);
    free(str2);
    return 0;
}
