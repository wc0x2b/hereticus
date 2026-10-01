/* The second release of callee.c: `pick` calls `beta` now. */
extern int alpha(int);
extern int beta(int);
extern int gamma_(int);

__attribute__((noinline)) static int scale(int x) { return x * 7 + 3; }

int keep(int x) { return gamma_(scale(x)) + 1; }

int pick(int x) { return beta(x) * 3; }
