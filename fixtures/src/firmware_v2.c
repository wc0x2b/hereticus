// Fixture firmware, the later version.
//
// Each difference from `firmware.c` is one recognizable kind of edit, so a
// test can name what the report should say. Keep the two files in step: a
// change here without a matching note there makes the expected answer wrong.
//
// Compiled by fixtures/build.sh at -O0, -O1, -O2 and -Os.

#include <stdint.h>

// The bound moved. The struct keeps its original size, so only the comparison
// changes and the layout of every access stays the same.
#define MAX_PAYLOAD 512
#define MAGIC 0x5A5A

struct packet {
    uint16_t magic;
    uint16_t len;
    uint8_t body[1024];
};

extern void log_event(int code);
extern int crypto_verify(const uint8_t *data, int len);

// Only the bound differs from the earlier version.
int validate_length(const struct packet *p) {
    if (p->len > MAX_PAYLOAD) return -1;
    return 0;
}

// Gained the authentication call and the branch that guards it.
int check_header(const struct packet *p) {
    if (p->magic != MAGIC) return -1;
    if (crypto_verify(p->body, p->len) != 0) return -2;
    return 0;
}

// Untouched, as a control.
uint32_t checksum(const uint8_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; i++) sum += data[i];
    return sum;
}

// Gained case 3, which grows the jump table.
int dispatch(const struct packet *p, int kind) {
    switch (kind) {
    case 0:
        return validate_length(p);
    case 1:
        return check_header(p);
    case 2:
        return (int)checksum(p->body, p->len);
    case 3:
        return crypto_verify(p->body, p->len);
    default:
        return -1;
    }
}

// Unedited. What changes here arrives through inlining.
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
