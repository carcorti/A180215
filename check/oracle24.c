/* Bounded target-side derivative of supplied MiniMax oracle2.c.
 * Changes only: fixed ceiling24, checked uint64 leaf counter, format.
 * No production code or new index; original reviewer file is immutable. */
/* Independent oracle #2 for A180215: enumerate the REALISATION vector x
 * directly (length n+4), derive p from the window relation, count distinct
 * ordered permutations p.  No zero-anchor split, no F table, no complementary
 * sum -- a structurally different path to the same numbers.
 *
 * Relation: p_i = x_i + 4x_{i+1} + 6x_{i+2} + 4x_{i+3} + x_{i+4}, i=0..n-1.
 * Building left-to-right, given x_{i-3..i} the value p_{i-3} = base + x_{i+1}
 * where base = x_{i-3} + 4x_{i-2} + 6x_{i-1} + 4x_i.  We therefore choose
 * x_0..x_3, then repeatedly choose x_{i+1} >= 0 and read off p_{i-3}.
 * p must stay in 0..n-1 and be pairwise distinct.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

static int n, M;
static uint32_t usedmask;
static unsigned long long leaves;
static int pv[64];



static void rec(int j, int a, int b, int c, int d) {
    /* j = number of p-values already produced; (a,b,c,d) = last four x */
    if (j == n) { if (leaves == ULLONG_MAX) { fputs("oracle count overflow\n", stderr); exit(2); } leaves++; return; }
    int base = a + 4 * b + 6 * c + 4 * d;
    if (base > M) return;
    for (int e = 0; base + e <= M; e++) {
        int v = base + e;
        if (usedmask >> v & 1u) continue;
        int nb = b + 4 * c + 6 * d + 4 * e;   /* next base */
        if (j + 1 < n && nb > M) break;        /* dead branch */
        usedmask |= 1u << v;
        pv[j] = v;
        rec(j + 1, b, c, d, e);
        usedmask &= ~(1u << v);
    }
}

int main(void) {
    const int nmax = 24; /* Fixed known-domain ceiling, no CLI extension. */
    for (n = 1; n <= nmax; n++) {
        M = n - 1;
        leaves = 0; usedmask = 0;
        for (int a = 0; a <= M; a++)
            for (int b = 0; b * 4 <= M; b++)
                for (int c = 0; c * 6 <= M; c++)
                    for (int d = 0; d * 4 <= M; d++) {
                        if (a + 4 * b + 6 * c + 4 * d > M) continue;
                        rec(0, a, b, c, d);
                    }
        printf("n=%2d distinct_permutations=%llu\n", n, leaves);
        fflush(stdout);
    }
    return 0;
}
