// A table of handler addresses, as a MIPS firmware image holds.
//
// The MIPS twin of vectors.s. The C fixtures hold no absolute addresses, so
// this is the only MIPS fixture that can exercise the load-address check. It
// is assembled in both byte orders, which makes the check read each stored
// word in the order of the image.
//
// Linked at 0x80000000, the start of KSEG0, by fixtures/build.sh.
        .set    noreorder
        .section .text
        .global _start

_start:
        .word   reset
        .word   fault
        .word   irq
        // A pointer to somewhere further into the image, as a table of
        // handlers would hold.
        .word   0x80000100

reset:
        jr      $ra
        addiu   $v0, $zero, 1

fault:
        jr      $ra
        addiu   $v0, $zero, 2

irq:
        jr      $ra
        addiu   $v0, $zero, 3

        // Pad out to the address the fourth word points at, so that word
        // lands inside the image.
        .space  0x100 - (. - _start)

late_handler:
        jr      $ra
        addiu   $v0, $zero, 4
