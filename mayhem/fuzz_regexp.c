// mayhem/fuzz_regexp.c — libFuzzer harness for sqlean's `regexp` extension.
//
// Exercises the extension's own C API (src/regexp/regexp.c): regexp_compile()
// compiles an untrusted PATTERN through the bundled PCRE2 with the same
// options the SQLite regexp()/regexp_like() functions use (PCRE2_UCP |
// PCRE2_UTF, set inside regexp_compile itself — see src/regexp/regexp.c).
//
// Input format (no filesystem, no SQLite needed — regexp.c has zero SQLite
// dependency): the fuzzer bytes are split on the FIRST '\n' into
//   pattern = bytes before '\n'      (NUL-terminated for pcre2_compile)
//   subject = bytes after '\n'       (NUL-terminated for pcre2_match)
// If there is no '\n', the whole input is the pattern and the subject is
// empty. Real seed patterns/subjects are harvested from upstream's own
// test/regexp.sql (see mayhem/fuzz_regexp/testsuite/).
//
// HANG GUARD (SPEC §6b — a hang stops the whole campaign, unlike a crash):
// regexp_like()/regexp_extract()/regexp_replace() in src/regexp/regexp.c all
// call pcre2_match() with a NULL pcre2_match_context, i.e. NO match/depth
// limit. A pathological pattern (catastrophic backtracking, e.g. nested
// quantifiers matched against a long non-matching subject) can then run
// pcre2_match() for a very long time — libFuzzer's default per-input timeout
// is 1200s, so one such input burns the whole run. Upstream's own PCRE2 fuzz
// harness (src/regexp/pcre2/pcre2_fuzzsupport.c) hits exactly this and fixes
// it by setting pcre2_set_match_limit()/pcre2_set_depth_limit() on a match
// context before calling pcre2_match() directly — we do the same here rather
// than through the unbounded wrapper, narrowly bounding only the match step
// (compilation, which is where most real defects live, stays untouched and
// uses the real regexp_compile()). This does not mask crashes/OOMs — only
// caps the pathological-backtracking runtime, exactly like upstream's own
// fuzzer does.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "regexp/pcre2/pcre2.h"
#include "regexp/regexp.h"

// Real PCRE2 limits (upstream pcre2_fuzzsupport.c uses 100; we allow more
// headroom since sqlean's patterns are typically short SQL regexes, while
// still bounding worst-case pathological backtracking to a few seconds).
#define MATCH_LIMIT 20000
#define DEPTH_LIMIT 5000
#define MAX_SUBJECT 4096

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return 0;
    }

    const uint8_t* nl = memchr(data, '\n', size);
    size_t pattern_len = nl ? (size_t)(nl - data) : size;
    const uint8_t* subject_data = nl ? nl + 1 : data + size;
    size_t subject_len = nl ? (size_t)(data + size - subject_data) : 0;
    if (subject_len > MAX_SUBJECT) {
        subject_len = MAX_SUBJECT;
    }

    char* pattern = malloc(pattern_len + 1);
    char* subject = malloc(subject_len + 1);
    if (!pattern || !subject) {
        free(pattern);
        free(subject);
        return 0;
    }
    memcpy(pattern, data, pattern_len);
    pattern[pattern_len] = '\0';
    memcpy(subject, subject_data, subject_len);
    subject[subject_len] = '\0';

    // regexp_compile: the actual extension code (unbounded compile — real
    // defects belong here and stay fuzzable at full strength).
    pcre2_code* re = regexp_compile(pattern);
    if (re != NULL) {
        // Bounded match (see header comment): same compiled pattern
        // (same options as regexp_like), but with match/depth limits so a
        // catastrophic-backtracking pattern can't stall the whole campaign.
        pcre2_match_data* match_data = pcre2_match_data_create_from_pattern(re, NULL);
        pcre2_match_context* match_context = pcre2_match_context_create(NULL);
        if (match_data != NULL && match_context != NULL) {
            pcre2_set_match_limit(match_context, MATCH_LIMIT);
            pcre2_set_depth_limit(match_context, DEPTH_LIMIT);
            pcre2_match(re, (PCRE2_SPTR8)subject, (PCRE2_SIZE)subject_len, 0, 0, match_data,
                        match_context);
        }
        if (match_data != NULL) {
            pcre2_match_data_free(match_data);
        }
        if (match_context != NULL) {
            pcre2_match_context_free(match_context);
        }
        regexp_free(re);
    } else {
        // Compilation failed — exercise the error-message path too (a
        // second, independent regexp_compile() call inside, so it's cheap
        // and still tests real extension code with the same pattern).
        char* err = regexp_get_error(pattern);
        free(err);
    }

    free(pattern);
    free(subject);
    return 0;
}
