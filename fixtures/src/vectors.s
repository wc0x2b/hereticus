// A vector table, as a firmware image starts with.
//
// This is the only fixture that holds absolute addresses. The C fixtures
// compile to position-independent code whose literal pools hold offsets, so
// they cannot exercise the load-address check at all. Here the first words are
// real addresses, which is what makes a wrong base visible.
//
// Linked at 0x08000000 by fixtures/build.sh.
        .arch armv7-a
        .arm
        .section .text
        .global _start

_start:
        .word   reset
        .word   fault
        .word   irq
        // A pointer to somewhere further into the image, as a table of
        // handlers would hold.
        .word   0x08000100

reset:
        mov     r0, #1
        bx      lr

fault:
        mov     r0, #2
        bx      lr

irq:
        mov     r0, #3
        bx      lr

        // Pad out to the address the fourth word points at, so that word
        // lands inside the image.
        .space  0x100 - (. - _start)

late_handler:
        mov     r0, #4
        bx      lr
