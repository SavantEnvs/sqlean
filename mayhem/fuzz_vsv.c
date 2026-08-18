// mayhem/fuzz_vsv.c — libFuzzer harness for sqlean's `vsv` extension (CSV /
// "variably separated values" virtual table, src/vsv/extension.c).
//
// vsv's real parsing code (vsv_read_one_field() and friends) is `static` and
// only reachable through SQLite's virtual-table machinery — there is no
// exported "parse this CSV buffer" C function. So this harness drives it
// through SQLite (style (b) from the integration brief): an in-memory
// (":memory:") database, the extension registered directly via its real
// entry point `vsv_init(db)` (the same call sqlite3-vsv.c's loadable-
// extension wrapper makes), and a FIXED SQL statement — only the CSV `data=`
// payload is fuzzer-controlled, embedded safely via sqlite3_mprintf's `%Q`
// (which quotes/escapes it as a SQL string literal; this is the only
// "extra" step, not a change to the SQL shape).
//
// No filesystem: `:memory:` only, and vsv is driven via `data=`, never
// `filename=` — the harness never touches disk.
//
// Coverage: SELECT * walks every row/column vsv produces (vsvtabFilter /
// vsvtabNext / vsvtabColumn), so both the field reader and the affinity/
// UTF-8-validation column formatting code get exercised. `validatetext=yes`
// and `affinity=numeric` are fixed on so the harness reaches vsv_utf8IsValid
// and vsv_isValidNumber every run, not just the plain-text default path.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sqlite3.h"
#include "vsv/extension.h"

#define MAX_DATA 65536

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > MAX_DATA) {
        return 0;
    }

    // NUL-terminate a copy: %Q formats a C string, and the fuzzer buffer is
    // neither NUL-terminated nor guaranteed free of embedded NULs (which
    // would simply truncate the CSV payload there — not a harness bug, just
    // a length limitation shared with any C-string-based embedding).
    char* buf = malloc(size + 1);
    if (!buf) {
        return 0;
    }
    memcpy(buf, data, size);
    buf[size] = '\0';

    sqlite3* db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        sqlite3_close(db);
        free(buf);
        return 0;
    }
    vsv_init(db);

    char* create_sql = sqlite3_mprintf(
        "CREATE VIRTUAL TABLE t USING vsv(data=%Q, header=no, validatetext=yes, "
        "affinity=numeric)",
        buf);
    if (create_sql != NULL && sqlite3_exec(db, create_sql, NULL, NULL, NULL) == SQLITE_OK) {
        sqlite3_stmt* stmt = NULL;
        if (sqlite3_prepare_v2(db, "SELECT * FROM t", -1, &stmt, NULL) == SQLITE_OK) {
            int steps = 0;
            // Bound the walk — a crafted CSV can encode a huge number of
            // rows relative to its byte size; cap iterations, not bytes, so
            // the fuzzer stays fast without touching the parser's own logic.
            while (steps < 100000 && sqlite3_step(stmt) == SQLITE_ROW) {
                int ncol = sqlite3_column_count(stmt);
                for (int i = 0; i < ncol; i++) {
                    switch (sqlite3_column_type(stmt, i)) {
                        case SQLITE_TEXT:
                            (void)sqlite3_column_text(stmt, i);
                            break;
                        case SQLITE_BLOB:
                            (void)sqlite3_column_blob(stmt, i);
                            break;
                        case SQLITE_INTEGER:
                            (void)sqlite3_column_int64(stmt, i);
                            break;
                        case SQLITE_FLOAT:
                            (void)sqlite3_column_double(stmt, i);
                            break;
                        default:
                            break;
                    }
                }
                steps++;
            }
            sqlite3_finalize(stmt);
        }
    }
    sqlite3_free(create_sql);
    sqlite3_close(db);
    free(buf);
    return 0;
}
