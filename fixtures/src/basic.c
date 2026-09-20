// Fixture functions for tech-heresy tests.
//
// These cover the shapes that make function matching hard: arithmetic that the
// optimizer folds, loops it unrolls or rewrites, branches it reorders, and
// switches it turns into jump tables. Each function must keep the same
// observable behavior at every optimization level, so a matcher that works
// must pair them across levels.
//
// Compiled by fixtures/build.sh at -O0, -O1, -O2 and -Os.

// Trivial: at -O0 this builds a full stack frame, at -O2 it is two
// instructions. The widest codegen gap in the corpus.
int add(int a, int b) { return a + b; }

// The optimizer can replace the multiply with shifts and adds.
int mul_by_constant(int x) { return x * 37; }

// A counted loop. Expect unrolling at higher levels.
int sum_to(int n) {
    int total = 0;
    for (int i = 0; i <= n; i++) {
        total += i;
    }
    return total;
}

// Nested branches. Block order and condition polarity often change.
int classify(int x) {
    if (x < 0) {
        return -1;
    } else if (x == 0) {
        return 0;
    } else if (x < 100) {
        return 1;
    }
    return 2;
}

// Dense switch. Becomes a jump table when the optimizer decides it is worth it.
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

// Calls another function in the same object, so the call graph has an edge.
int call_chain(int x) { return add(mul_by_constant(x), 1); }

// Pointer and memory work, to exercise load/store forms.
int array_max(const int *values, int count) {
    if (count <= 0) {
        return 0;
    }
    int best = values[0];
    for (int i = 1; i < count; i++) {
        if (values[i] > best) {
            best = values[i];
        }
    }
    return best;
}

// Recursion, which the optimizer may turn into a loop.
int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}
