// Fixture firmware, the earlier version.
//
// `basic.c` covers the shapes that make matching hard. This pair covers what
// the report says once a pair is found: each function here changes in one
// recognizable way in `firmware_v2.c`, so the reported kind of edit can be
// checked against a known answer.
//
// The shape is a packet handler, because that is where the distinction earns
// its keep: an added call to an authentication routine reads very differently
// from a bound that moved, and both arrive as "changed".
//
// Compiled by fixtures/build.sh at -O0, -O1, -O2 and -Os.

#include <stdint.h>

#define MAX_PAYLOAD 1024
#define MAGIC 0x5A5A

struct packet {
    uint16_t magic;
    uint16_t len;
    uint8_t body[MAX_PAYLOAD];
};

// Not defined here, so the compiler must emit a real call it cannot inline.
extern void log_event(int code);
extern int crypto_verify(const uint8_t *data, int len);

// The bound moves in the later version and nothing else does, so every
// instruction stays in place and only the stored value differs.
int validate_length(const struct packet *p) {
    if (p->len > MAX_PAYLOAD) return -1;
    return 0;
}

// Gains a call to `crypto_verify` in the later version. A leaf function
// becomes a non-leaf one, which is the largest change in this file.
int check_header(const struct packet *p) {
    if (p->magic != MAGIC) return -1;
    return 0;
}

// Untouched between the two versions, as a control. Any report of a change
// here is a false positive.
uint32_t checksum(const uint8_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; i++) sum += data[i];
    return sum;
}

// Gains a case in the later version, which grows the jump table.
int dispatch(const struct packet *p, int kind) {
    switch (kind) {
    case 0:
        return validate_length(p);
    case 1:
        return check_header(p);
    case 2:
        return (int)checksum(p->body, p->len);
    default:
        return -1;
    }
}

// Edited nowhere, but inlining pulls the other edits in. This is where a
// changed constant hides inside a larger rewrite.
int handle(const struct packet *p) {
    if (check_header(p) < 0) {
        log_event(1);
        return -1;
    }
    if (validate_length(p) < 0) {
        log_event(2);
        return -1;
    }
    return dispatch(p, 2);
}
