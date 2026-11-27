/* What a kernel module reaches through relocations: an array another
 * object defines, a text it passes, and data of its own. */
extern int table[64];
extern void report(const char *message, int value);
static int counter;
int seen[4];

void note(int value) { counter += value; report("counter changed", counter); }

int read_table(int i) { return table[i & 63]; }

int *slot(int i) { return &seen[i & 3]; }
