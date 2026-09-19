// Version 2 of basic.c, used as the "after" side of a diff.
//
// Most functions are byte-identical in source. Three changed on purpose, and
// those three are the ground truth for change detection:
//
//   mul_by_constant  the constant differs (37 -> 41)
//   classify         a threshold differs (100 -> 50)
//   array_max        finds the minimum instead of the maximum
//
// Every other function must be reported as unchanged. A matcher that flags
// them has false positives; one that misses the three above has false
// negatives.

int add(int a, int b) { return a + b; }

// CHANGED: constant is now 41.
int mul_by_constant(int x) { return x * 41; }

int sum_to(int n) {
    int total = 0;
    for (int i = 0; i <= n; i++) {
        total += i;
    }
    return total;
}

// CHANGED: the third threshold is now 50.
int classify(int x) {
    if (x < 0) {
        return -1;
    } else if (x == 0) {
        return 0;
    } else if (x < 50) {
        return 1;
    }
    return 2;
}

int switch_dense(int x) {
    switch (x) {
        case 0: return 10;
        case 1: return 20;
        case 2: return 30;
        case 3: return 40;
        case 4: return 50;
        case 5: return 60;
        default: return -1;
    }
}

int call_chain(int x) { return add(mul_by_constant(x), 1); }

// CHANGED: returns the minimum, not the maximum.
int array_min(const int *values, int count) {
    if (count <= 0) {
        return 0;
    }
    int best = values[0];
    for (int i = 1; i < count; i++) {
        if (values[i] < best) {
            best = values[i];
        }
    }
    return best;
}

int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}
