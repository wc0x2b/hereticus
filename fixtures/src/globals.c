/* Relocated address loads that a non-PIC build opens with the same two words
 * as the MIPS PIC preamble: `lui rX, 0x0` then `addiu rX, rX, 0x0`. Dropping
 * that pair on its shape alone would delete a real memory reference here, so
 * these functions are the check that it is kept. */
extern int table[64];
extern int other[64];

int read_table(int i) { return table[i & 63]; }

/* The same shape against a different global. If the address load is dropped,
 * this and `read_table` normalize alike and the matcher cannot tell them
 * apart. */
int read_other(int i) { return other[i & 63]; }

/* A wide constant the linker has already filled in, so the immediate is not
 * zero and the pair never looks like the preamble. */
int wide_mask(int v) { return v & 0x12345678; }

/* Two loads whose halves the compiler interleaves, so the pair is not even
 * adjacent. */
int both_globals(void) { return table[0] + other[17]; }
