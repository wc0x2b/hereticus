// The run-time helpers the ARM EABI names and a bare-metal image supplies
// itself: Cortex-M0 has no divide instruction, and clang clears structs with
// a call. Built with -fno-builtin, so a loop here stays a loop.
#include <stddef.h>

void __aeabi_memclr4(void *destination, size_t length) {
    unsigned char *byte = destination;
    while (length-- > 0) {
        *byte++ = 0;
    }
}

// Shift and subtract, one bit of the quotient at a time. Returns the
// quotient in the low word and the remainder in the high word, which is
// r0 and r1, as `__aeabi_uidivmod` returns them.
unsigned long long __aeabi_uidivmod(unsigned numerator, unsigned denominator) {
    unsigned quotient = 0;
    unsigned remainder = 0;
    for (int bit = 31; bit >= 0; bit--) {
        remainder = (remainder << 1) | ((numerator >> bit) & 1);
        if (remainder >= denominator) {
            remainder -= denominator;
            quotient |= 1u << bit;
        }
    }
    return ((unsigned long long)remainder << 32) | quotient;
}

unsigned __aeabi_uidiv(unsigned numerator, unsigned denominator) {
    return (unsigned)__aeabi_uidivmod(numerator, denominator);
}
