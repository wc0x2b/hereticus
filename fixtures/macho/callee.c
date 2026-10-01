/* A pair for the Mach-O tests: `pick` calls `alpha` here and `beta` in
 * callee_v2.c, through a stub, and nothing else changes. `scale` is static,
 * so stripping removes its name and leaves the others. */
extern int alpha(int);
extern int beta(int);
extern int gamma_(int);

__attribute__((noinline)) static int scale(int x) { return x * 7 + 3; }

int keep(int x) { return gamma_(scale(x)) + 1; }

int pick(int x) { return alpha(x) * 3; }
