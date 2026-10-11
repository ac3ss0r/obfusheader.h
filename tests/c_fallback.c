/* Test TU for the C fallback path: OBF()/CALL()/HIDE_PTR() degrade to the raw
   value, while the control flow mutation and the inline stdlib still work in C. */
#include <stdio.h>
#include <string.h>

#include "..\include\obfusheader.h"

static int failures = 0;

#define CHECK(cond)                     \
    do {                                \
        if (!(cond)) {                  \
            ++failures;                 \
            printf("FAILED line %d: %s\n", __LINE__, #cond); \
        }                               \
    } while (0)

static int add(int a, int b) { return a + b; }

int main(void) {
    /* C has no constexpr, so OBF() is identity here */
    CHECK(OBF(123) == 123);
    CHECK(strcmp(OBF("c path string"), "c path string") == 0);
    CHECK(OBF(1) == 1);

    /* the keyword mutation must keep semantics in C too */
    int sum = 0;
    for (int i = 1; i <= 10; ++i) sum += i;
    CHECK(sum == 55);

    int k = 0;
    while (k < 5) ++k;
    CHECK(k == 5);

    int v = 2, out = 0;
    if (v > 0) out = 1; else out = -1;
    CHECK(out == 1);

    switch (v) { case 1: out = 10; break; case 2: out = 20; break; default: out = 30; }
    CHECK(out == 20);

    /* C call hiding degrades to a direct call */
    CHECK(CALL(add, 2, 3) == 5);

#if INLINE_STD
    CHECK(inline_strcmp("abc", "abc") == 0);
    CHECK(inline_strlen("abcd") == 4);
#endif

    ASM_JUNK;
    STACKBRK;
    INDIRECT_BRANCH;

    printf("c checks done, failures=%d\n", failures);
    return failures;
}
