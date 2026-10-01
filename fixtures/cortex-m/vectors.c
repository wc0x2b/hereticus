// The start of a Cortex-M image: the vector table, and the handlers it names.
//
// The table opens the image. Its first word is where the stack starts, and
// each word after it is the address of a handler with bit 0 set, as Thumb
// code is marked. A scan of the raw image can read every handler's start
// from it. The reset handler runs zlib, so the library is code the image
// uses, as firmware that unpacks an update would.
#include "zlib.h"

extern unsigned long stack_top;

void reset_handler(void);
void default_handler(void);

__attribute__((section(".vectors"), used)) static void (*const vectors[])(void) = {
    (void (*)(void))&stack_top,
    reset_handler,   // Reset
    default_handler, // NMI
    default_handler, // HardFault
    default_handler, // MemManage
    default_handler, // BusFault
    default_handler, // UsageFault
    0,
    0,
    0,
    0,
    default_handler, // SVCall
    default_handler, // DebugMonitor
    0,
    default_handler, // PendSV
    default_handler, // SysTick
};

static unsigned char window[1 << 15];
static unsigned char packed[64];
static unsigned char unpacked[256];

void reset_handler(void) {
    z_stream stream = {0};
    stream.next_in = packed;
    stream.avail_in = sizeof packed;
    stream.next_out = unpacked;
    stream.avail_out = sizeof unpacked;
    (void)window;
    if (inflateInit(&stream) == Z_OK) {
        (void)inflate(&stream, Z_FINISH);
        (void)inflateEnd(&stream);
    }
    for (;;) {
    }
}

void default_handler(void) {
    for (;;) {
    }
}
