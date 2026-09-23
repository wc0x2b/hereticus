/* Functions that each make an external call, so a PIC build must set up $gp
 * in every one of them. Non-leaf on purpose: a leaf never touches $gp. */
extern int alpha(int);
extern int beta(int, int);
extern int gamma_(int, int, int);
extern void sink(int);

int sum_calls(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += alpha(i);
    return total;
}

int mix_two(int a, int b) { return beta(a, b) + alpha(a) - b; }

int guarded(int n) {
    if (n < 0) return -1;
    if (n > 100) return alpha(n);
    return beta(n, 2);
}

int chain_three(int x) { return gamma_(alpha(x), beta(x, x), x); }

int loop_sink(int n) {
    for (int i = 0; i < n; i++) sink(i * 3);
    return n;
}

int table(int which, int v) {
    switch (which) {
        case 0: return alpha(v);
        case 1: return beta(v, 1);
        case 2: return gamma_(v, 1, 2);
        case 3: return alpha(v) + beta(v, v);
        default: return -1;
    }
}

int accumulate(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) total += beta(values[i], total);
    return total;
}

int nested(int a) {
    int r = alpha(a);
    if (r > 10) {
        r = beta(r, a);
        if (r > 100) r = gamma_(r, a, 1);
    }
    return r;
}
