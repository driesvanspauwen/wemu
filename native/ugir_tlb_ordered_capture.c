/*
 * Optional timer wrapper for an existing four-row UGIR Flexo-TLB AND object.
 *
 * Link this in place of UGIR's histogram-only rpl_instr.o. It does not modify
 * the gate object. It buffers timer returns, then emits both the original
 * histogram protocol and ordered UCAP v1 rows after the final timer call.
 * Extra writes can perturb the experiment; compare with the original wrapper
 * before treating any outcome as silicon evidence.
 */

#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int64_t WR_HIT_THRESHOLD;
extern uint64_t timer_raw(void *address);

enum { ROWS = 4, HIST_BINS = 400, JOINT_BINS = 200, MAX_TRIALS = 10000 };

static uint32_t histogram[ROWS][2][HIST_BINS];
static uint32_t joint[ROWS][JOINT_BINS][JOINT_BINS];
static uint64_t *latencies;
static size_t expected_calls;
static size_t calls;
static int dumped;
static unsigned capture_seed;

static int parse_uint(const char *source, uint64_t maximum, uint64_t *result) {
    if (!source || *source < '0' || *source > '9') return 0;
    char *end;
    errno = 0;
    unsigned long long value = strtoull(source, &end, 10);
    if (errno || *end || value > maximum) return 0;
    *result = (uint64_t)value;
    return 1;
}

static size_t cap(uint64_t value, size_t bins) {
    return value < bins - 1 ? (size_t)value : bins - 1;
}

static void dump_capture(void) {
    if (dumped || calls != expected_calls || !latencies) return;
    dumped = 1;
    printf("UCAP_CONFIG v=1 gate=AND rows=4 n=%zu threshold=%" PRId64
           " seed=%u\n", expected_calls / (2 * ROWS), WR_HIT_THRESHOLD,
           capture_seed);
    for (size_t row = 0; row < ROWS; row++) {
        for (int rail = 1; rail >= 0; rail--) {
            printf("H row=%zu,%zu rail=%d", row & 1, row >> 1, rail);
            for (size_t bin = 0; bin < HIST_BINS; bin++) {
                if (histogram[row][rail][bin])
                    printf(" %zu:%u", bin, histogram[row][rail][bin]);
            }
            printf("\n");
        }
    }
    for (size_t row = 0; row < ROWS; row++) {
        printf("J row=%zu,%zu", row & 1, row >> 1);
        for (size_t a = 0; a < JOINT_BINS; a++) {
            for (size_t b = 0; b < JOINT_BINS; b++) {
                if (joint[row][a][b])
                    printf(" %zu,%zu:%u", a, b, joint[row][a][b]);
            }
        }
        printf("\n");
    }
    for (size_t trial = 0; trial < expected_calls / 2; trial++) {
        size_t row = trial % ROWS;
        printf("UCAP v=1 seq=%zu row=%zu,%zu rail1=%" PRIu64
               " rail0=%" PRIu64 "\n", trial, row & 1, row >> 1,
               latencies[2 * trial], latencies[2 * trial + 1]);
    }
    fflush(stdout);
}

__attribute__((constructor)) static void configure_capture(void) {
    uint64_t threshold, seed, rows, count;
    if (!parse_uint(getenv("UGIR_THR"), INT64_MAX, &threshold) || threshold == 0 ||
        !parse_uint(getenv("UGIR_SEED"), UINT_MAX, &seed) ||
        !parse_uint(getenv("UGIR_ROWS"), ROWS, &rows) || rows != ROWS ||
        !parse_uint(getenv("UGIR_N"), MAX_TRIALS, &count) || count == 0) return;
    WR_HIT_THRESHOLD = (int64_t)threshold;
    capture_seed = (unsigned)seed;
    srand(capture_seed);
    expected_calls = 2 * ROWS * (size_t)count;
    latencies = calloc(expected_calls, sizeof(*latencies));
    if (!latencies) expected_calls = 0;
}

uint64_t timer(void *address) {
    uint64_t elapsed = timer_raw(address);
    if (!latencies || calls >= expected_calls) return elapsed;
    size_t call = calls++;
    size_t row = (call / 2) % ROWS;
    int rail = (call & 1) ? 0 : 1;
    latencies[call] = elapsed;
    histogram[row][rail][cap(elapsed, HIST_BINS)]++;
    if (rail == 0) {
        size_t first = cap(latencies[call - 1], JOINT_BINS);
        joint[row][first][cap(elapsed, JOINT_BINS)]++;
    }
    if (calls == expected_calls) dump_capture();
    return elapsed;
}
