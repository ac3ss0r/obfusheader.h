// Automated self-test for obfusheader.h.
//
// Unlike cpp_tests.cpp this file never waits for input: it asserts on behaviour and
// exits with the number of failures, so it can be run in a loop over compilers,
// optimization levels and configuration flags.
//
//   g++ -std=c++14 -O2 -I../include selftest.cpp -o selftest.exe && selftest.exe
//   cl  /std:c++14 /O2 /I../include selftest.cpp && selftest.exe
//
#include <stdio.h>
#include <string.h>

#include "../include/obfusheader.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond)                                                \
    do {                                                           \
        ++checks;                                                  \
        if (!(cond)) {                                             \
            ++failures;                                            \
            printf("FAILED line %d: %s\n", __LINE__, #cond);       \
        }                                                          \
    } while (0)

NOINLINE void set_int(int* dst, int value) { *dst = value; }
NOINLINE int get_int(int value) { return value; }
NOINLINE int no_args() { return 42; }
NOINLINE int returning_ifelse(bool value) {
    if (value) return 17;
    else return 29;
}
// Hidden calls must also work during static initialization, before main.
static const int early_call = CALL(&no_args);

// Local copy helper: the tests must not depend on INLINE_STD being on, and libc's
// strcpy makes MSVC emit C4996 in every build.
static void plain_copy(char* dst, const char* src) {
    while ((*dst++ = *src++) != 0)
        ;
}

// ----------------------------------------------------- bool encryption (issue 2)
// Encrypting a bool used to require "#define true 1" and "#define false 0": the
// payload was stored in a bool, so the key was truncated to one bit at encrypt time
// while the decryptor tested for non-zero, and OBF(true) silently came back false.
static void test_bool_encryption() {
    CHECK(OBF(true) == true);
    CHECK(OBF(false) == false);
    CHECK(OBF(true) != false);
    CHECK(OBF(false) != true);

    bool t = OBF(true);
    bool f = OBF(false);
    CHECK(t == true);
    CHECK(f == false);
    CHECK((int)OBF(true) == 1);
    CHECK((int)OBF(false) == 0);

    // both bools must stay distinguishable, not collapse onto the same value
    CHECK((OBF(true) ? 1 : 0) + (OBF(false) ? 1 : 0) == 1);

    // `true`/`false` are real keywords again: they still work as template arguments
    meta::integral_constant<bool, true> one;
    meta::integral_constant<bool, false> zero;
    CHECK((bool)one == true);
    CHECK((bool)zero == false);
    CHECK(one() == true);
}

static void test_scalar_encryption() {
    CHECK(OBF(0) == 0);
    CHECK(OBF(1) == 1);
    CHECK(OBF(123) == 123);
    CHECK(OBF(-1) == -1);
    CHECK(OBF(-987654321) == -987654321);
    CHECK(OBF(0x123) == 0x123);
    CHECK(OBF(017) == 15);
    CHECK(OBF(65535) == 65535);
    CHECK(OBF(9223372036854775807LL) == 9223372036854775807LL);
    CHECK(OBF((-9223372036854775807LL - 1)) == (-9223372036854775807LL - 1));
    CHECK(OBF(0xFFFFFFFFFFFFFFFFull) == 0xFFFFFFFFFFFFFFFFull);
    CHECK(OBF('A') == 'A');

    // the same literal twice in one expression, then repeatedly across statements
    CHECK(OBF(77) + OBF(77) == 154);
    for (int i = 0; i < 5; ++i)
        CHECK(OBF(2026) == 2026);
}

static void test_string_encryption() {
    CHECK(strcmp(OBF("test"), "test") == 0);
    CHECK(strcmp(OBF(""), "") == 0);
    CHECK(strlen(OBF("hello world")) == 11);
    CHECK(strcmp(OBF("a longer string that goes past a single cipher block by a wide margin"),
                 "a longer string that goes past a single cipher block by a wide margin") == 0);

    // two uses of identical contents must decrypt independently of each other
    CHECK(strcmp(OBF("dup"), "dup") == 0);
    CHECK(strcmp(OBF("dup"), "dup") == 0);
    CHECK(strcmp(OBF("dup"), OBF("dup")) == 0);
    CHECK(strcmp(OBF("short"), OBF("short")) == 0);

    for (int i = 0; i < 5; ++i)
        CHECK(strcmp(OBF("again and again"), "again and again") == 0);

    // MAKEOBF hands out a durable object: repeated decryption must stay correct
    auto held = MAKEOBF("held payload");
    CHECK(strcmp((char*)held, "held payload") == 0);
    CHECK(strcmp((char*)held, "held payload") == 0);
    CHECK(strlen((char*)held) == 12);
}

static void test_array_encryption() {
    // OBF() hands out a pointer into a temporary, so it has to be consumed inside the
    // same full-expression. Storing it in a variable is the documented unsafe pattern
    // and the copy can be recycled before it is read.
    static constexpr short table[] = { 1, 2, 3, 4, 5 };
    CHECK(OBF(table)[0] == 1);
    CHECK(OBF(table)[3] == 4);
    CHECK(OBF(table)[4] == 5);

    char buf[16];
    plain_copy(buf, OBF("abcdef"));
    CHECK(strcmp(buf, "abcdef") == 0);
    CHECK(strlen(OBF("abcdef")) == 6);
}

// --------------------------------------------------------------- call hiding
static void test_call_hiding() {
    CHECK(early_call == 42);
    int value = 0;
    CALL(&set_int, &value, 123);
    CHECK(value == 123);
    CHECK(CALL(&get_int, 321) == 321);
    CHECK(CALL(&no_args) == 42);

    // several hidden calls in one scope, each picks its own random slot
    int a = 0, b = 0;
    CALL(&set_int, &a, 1);
    CALL(&set_int, &b, 2);
    CHECK(a + b == 3);

    // an explicit slot index must agree with the table it selects
    int direct = 0;
    HIDE_PTR_I(&set_int, CALL_SLOTS - 1)(&direct, 9);
    CHECK(direct == 9);

    CHECK(HIDE_PTR(&get_int)(7) == 7);
    CHECK(CALL(&get_int, CALL(&no_args)) == 42);
}

// ------------------------------------------------------------- hash agreement
// A compile-time OBF_HASH() has to equal the run-time hash over the loader's own
// name table, otherwise import hiding silently resolves nothing.
static void test_hash_agreement() {
    CHECK(OBF_HASH("GetCurrentProcessId") == obf::hash_runtime("GetCurrentProcessId"));
    CHECK(OBF_HASH("test") == obf::hash_runtime("test"));
    CHECK(OBF_HASH("a") == obf::hash_runtime("a"));
    CHECK(OBF_HASH("x") != obf::hash_runtime("y"));
    CHECK(OBF_HASH_LOWER("KERNEL32.DLL") == OBF_HASH_LOWER("kernel32.dll"));
    CHECK(OBF_HASH_LOWER("kernel32.dll") != OBF_HASH_LOWER("ntdll.dll"));
    CHECK(OBF_ELF_HASH("GetCurrentProcessId") == obf::hash_elf("GetCurrentProcessId"));
    // the salt makes every build's hashes different, so it cannot be a fixed constant
    CHECK(OBF_HASH("GetCurrentProcessId") != obf::hash_fnv("GetCurrentProcessId"));
}

// ------------------------------------------------------------- import hiding
static void test_import_hiding() {
#if OBF_WINDOWS
    typedef unsigned (*get_pid_t)();

    // the manual walk must land on exactly the address the loader reports
    void* manual = obf::pe::resolve(OBF_HASH_LOWER("kernel32.dll"), OBF_HASH("GetCurrentProcessId"));
    CHECK(manual != 0);
#if IMPORT_RESOLVER != OBF_RESOLVER_MANUAL
    void* api = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentProcessId");
    CHECK(manual == api);
#endif

    // a second module proves the walk is not pinned to one entry
    CHECK(obf::pe::resolve(OBF_HASH_LOWER("ntdll.dll"), OBF_HASH("RtlAllocateHeap")) != 0);

    // a miss must return null instead of garbage
    CHECK(obf::pe::resolve(OBF_HASH_LOWER("kernel32.dll"), OBF_HASH("NotARealExportName")) == 0);

    // resolved through the masked cache slot, and callable
    get_pid_t pid = (get_pid_t)obf::import_slot<OBF_HASH_LOWER("kernel32.dll"),
                                                 OBF_HASH("GetCurrentProcessId"),
                                                 OBF_ELF_HASH("GetCurrentProcessId"),
                                                 0x5A5Au>::get("kernel32.dll", "GetCurrentProcessId");
    CHECK(pid != 0);
    CHECK(pid() != 0);

    // the public macro form
    CHECK(CALL_EXPORT("kernel32.dll", "GetCurrentProcessId", get_pid_t) != 0);
    CHECK(CALL_EXPORT("kernel32.dll", "GetTickCount", get_pid_t) != 0);
#endif
}

// ------------------------------------------------------------- inline stdlib
static void test_inline_std() {
#if INLINE_STD
    CHECK(inline_strcmp("abc", "abc") == 0);
    CHECK(inline_strcmp("abc", "abd") < 0);
    CHECK(inline_strcmp("abd", "abc") > 0);
    CHECK(inline_strcmp("abc", "abcd") < 0);
    CHECK(inline_strncmp("abcxyz", "abcqrs", 3) == 0);
    CHECK(inline_strncmp("abcxyz", "abcqrs", 4) != 0);
    CHECK(inline_strlen("") == 0);
    CHECK(inline_strlen("hello") == 5);

    char cat[16];
    inline_strcpy(cat, "ab");
    inline_strncat(cat, "cd", 2);
    CHECK(strcmp(cat, "abcd") == 0);

    char cp[16];
    inline_strcpy(cp, "copy me");
    CHECK(strcmp(cp, "copy me") == 0);

    CHECK(inline_strstr("haystack needle", "needle") != 0);
    CHECK(inline_strstr("haystack", "nope") == 0);
    CHECK(inline_strtoul("ff", 0) == 255);

    // encrypted literals on both sides of a comparison
    CHECK(inline_strcmp(OBF("secret"), "secret") == 0);
    CHECK(inline_strcmp(OBF("secret"), OBF("secret")) == 0);
    CHECK(inline_strcmp(OBF("secret"), OBF("other")) != 0);
#endif
}

// -------------------------------------------------------- cflow correctness
// Each mutated keyword has to keep the original semantics. Counted side effects
// catch a guard loop that runs more than once or a fake branch that is taken.
static int g_flow_hits = 0;

static int flow_if_else(int v) {
    int result = 0;
    if (v > 0) {
        result = 1;
    } else if (v < 0) {
        result = -1;
    } else {
        result = 2;
    }
    if (v == 100)
        result += 10;
    else
        result += 0;
    return result;
}

static int flow_loops() {
    int sum = 0;
    for (int i = 1; i <= 10; ++i)
        sum += i;

    int last = 0;
    for (int i = 0, j = 0; i < 5; ++i)
        j = j + i, last = j;

    int k = 0;
    while (k < 4)
        ++k;

    do {
        ++k;
    } while (k < 5);

    ++g_flow_hits;
    return sum + last + k;
}

static int flow_switch(int v) {
    int out = 0;
    switch (v) {
        case 1:
            out = 10;
            break;
        case 2:
        case 3:
            out = 20;
            break;
        default:
            out = 30;
            break;
    }
    return out;
}

static int flow_nested() {
    int total = 0;
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 3; ++j) {
            if (i == j)
                total += 1;
            else if (i > j)
                total += 2;
            else
                total += 3;
        }
    }
    return total;
}

static int flow_early_return(int v) {
    if (v < 0)
        return -1;
    if (v == 0)
        return 0;
    int sum = 0;
    for (int i = 0; i < v; ++i) {
        if (i == 3)
            return 99;
        sum += i;
    }
    return sum;
}

static void* flow_return_ptr() {
    return (void*)1;
}

static void test_control_flow() {
    CHECK(flow_if_else(5) == 1);
    CHECK(flow_if_else(-5) == -1);
    CHECK(flow_if_else(0) == 2);
    CHECK(flow_if_else(100) == 11);

    g_flow_hits = 0;
    CHECK(flow_loops() == 70);   // 55 + (0+1+2+3+4) + 5
    CHECK(g_flow_hits == 1);     // the body ran exactly once

    CHECK(flow_switch(1) == 10);
    CHECK(flow_switch(2) == 20);
    CHECK(flow_switch(3) == 20);
    CHECK(flow_switch(9) == 30);

    CHECK(flow_nested() == 18);          // (1+3+3) + (2+1+3) + (2+2+1)
    CHECK(flow_early_return(-1) == -1);
    CHECK(flow_early_return(0) == 0);
    CHECK(flow_early_return(2) == 1);    // 0 + 1
    CHECK(flow_early_return(5) == 99);   // hits the early return at i == 3
    CHECK(flow_return_ptr() == (void*)1);

    // a comma expression inside a condition keeps C semantics
    int x = 0;
    if ((x = 1, x == 1))
        CHECK(true);
    else
        CHECK(false);
    CHECK(x == 1);
}

// ------------------------------------------------------ issue 5: cflow at compile time
// With CFLOW_ASM_JUNK=0 the mutated keywords must stay legal inside constant
// expressions: no inline asm, no volatile read, no non-constexpr call. Everything the
// hijacked keywords expand to therefore has to survive constexpr and static_assert.
#if !CFLOW_ASM_JUNK

constexpr int cf_sum(int n) {
    int total = 0;
    for (int i = 1; i <= n; ++i) {
        if (i % 2 == 0)
            total += i;
        else
            total += 1;
    }
    return total;
}

constexpr int cf_while(int n) {
    int k = 0;
    while (k < n)
        ++k;
    return k;
}

// case labels inside a constant expression are C++20, so the mutated switch is only
// exercised at compile time when the dialect actually allows it
#if __cplusplus >= 202002L
constexpr int cf_switch(int v) {
    switch (v) {
        case 1: return 10;
        case 2: return 20;
        default: return 30;
    }
}
#endif

constexpr int cf_branches(int v) {
    if (v > 10)
        return 2;
    else if (v > 0)
        return 1;
    else if (v < 0)
        return -1;
    return 0;
}

constexpr int cf_nested_loops(int n) {
    int acc = 0;
    for (int i = 0; i < n; ++i)
        for (int j = 0; j < n; ++j)
            if (i == j)
                acc += 1;
    return acc;
}

static_assert(cf_sum(6) == 15, "cf_sum");
static_assert(cf_sum(0) == 0, "cf_sum empty");
static_assert(cf_while(4) == 4, "cf_while");
#if __cplusplus >= 202002L
static_assert(cf_switch(1) == 10, "cf_switch case 1");
static_assert(cf_switch(2) == 20, "cf_switch case 2");
static_assert(cf_switch(7) == 30, "cf_switch default");
#endif
static_assert(cf_branches(50) == 2, "cf_branches high");
static_assert(cf_branches(5) == 1, "cf_branches mid");
static_assert(cf_branches(-5) == -1, "cf_branches negative");
static_assert(cf_branches(0) == 0, "cf_branches zero");
static_assert(cf_nested_loops(3) == 3, "cf_nested_loops diagonal");

// the same functions compiled through the mutated keywords, but called at run time,
// must agree with what the compiler proved
static void test_compile_time_flow() {
    CHECK(cf_sum(6) == 15);
    CHECK(cf_sum(0) == 0);
    CHECK(cf_while(4) == 4);
#if __cplusplus >= 202002L
    CHECK(cf_switch(1) == 10);
    CHECK(cf_switch(7) == 30);
#endif
    CHECK(cf_branches(5) == 1);
    CHECK(cf_branches(-5) == -1);
    CHECK(cf_nested_loops(3) == 3);
    CHECK(OBF(123) == 123);                    // encryption still works in this mode
    CHECK(strcmp(OBF("constexpr mode string"), "constexpr mode string") == 0);
}
#endif /* !CFLOW_ASM_JUNK */

// `if constexpr` is a different token sequence, so the function-like `if` macro never
// fires on it: this works even with the full asm mutation enabled, on C++17 and up.
#if defined(__cplusplus) && __cplusplus >= 201703L
template <class T>
static int constexpr_probe(T v) {
    if constexpr (sizeof(T) > 4)
        return (int)(v * 2);
    else
        return (int)v;
}
static void test_if_constexpr() {
    CHECK(constexpr_probe(3) == 3);
    CHECK(constexpr_probe((long long)3) == 6);
}
#endif

// ------------------------------------------------------------- misc features
// The leak scan needs literals that exist *only* inside OBF(): a plain copy used for
// strcmp would be present in the binary by definition. The constexpr hash is the
// plaintext-free equivalent - the compile-time hash is folded away, the run-time hash
// reads the decrypted row, and equality proves both directions at once.
static void test_misc() {
    CHECK(obf::hash_runtime(OBF("SELFTEST_MARKER_ALPHA")) == OBF_HASH("SELFTEST_MARKER_ALPHA"));
    CHECK(obf::hash_runtime(OBF("SELFTEST_MARKER_BRAVO_0123456789")) == OBF_HASH("SELFTEST_MARKER_BRAVO_0123456789"));
    CHECK(obf::hash_runtime(OBF("a long selftest marker that must never appear in the binary"))
          == OBF_HASH("a long selftest marker that must never appear in the binary"));
    CHECK(OBF("SELFTEST_MARKER_ALPHA")[0] == 'S');
    // lengths come from getsize() over the same literal (which is compile-time only),
    // so nothing is hand-counted and no plaintext copy is emitted
    CHECK(strlen(OBF("SELFTEST_MARKER_ALPHA")) == obf::getsize("SELFTEST_MARKER_ALPHA") - 1);
    CHECK(strlen(OBF("SELFTEST_MARKER_BRAVO_0123456789")) == obf::getsize("SELFTEST_MARKER_BRAVO_0123456789") - 1);
    CHECK(strlen(OBF("a long selftest marker that must never appear in the binary"))
          == obf::getsize("a long selftest marker that must never appear in the binary") - 1);
    // the cipher must actually differ from the plaintext on disk
    CHECK(OBF("SELFTEST_MARKER_ALPHA") != NULL);

#if WATERMARKING
    WATERMARK("self test watermark", "second line");
#endif
    INDIRECT_BRANCH;
    ASM_JUNK;
    STACKBRK;

    for (int i = 0; i < 200; ++i) {
        CHECK(RND(1, 10) >= 1 && RND(1, 10) <= 10);
        CHECK(RND(0, 0) == 0);
        CHECK(RND(-5, -1) >= -5 && RND(-5, -1) <= -1);
    }

    // encrypted literals directly in a call, as documented in the README
    printf("%s\n", OBF("strings work inside a call"));
    printf("%d %d\n", OBF(0x123), (int)OBF(true));
}

int main() {
    CHECK(returning_ifelse(true) == 17);
    CHECK(returning_ifelse(false) == 29);
    const unsigned long long high = 0xfedcba9876543210ull;
    switch (high) { case 0xfedcba9876543210ull: CHECK(true); break; default: CHECK(false); }
    enum class choice : unsigned long long { high = 0xfedcba9876543210ull };
    switch (choice::high) { case choice::high: CHECK(true); break; default: CHECK(false); }
    struct token {
        int& calls;
        explicit token(int& c) : calls(c) {}
        token(const token&) = delete;
        operator int() { ++calls; return 7; }
    };
    int conversions = 0;
    token context(conversions);
    switch (context) { case 7: CHECK(conversions == 1); break; default: CHECK(false); }
    switch (0x123456789abcdefLL) {
        case 0x123456789abcdefLL: CHECK(true); break;
        default: CHECK(false);
    }
    // Comma operands must be sequenced and only the final one converts to bool.
    int sequence = 0;
    if (++sequence, sequence *= 2, sequence == 2) { CHECK(sequence == 2); }
    else { CHECK(false); }
    switch (++sequence, sequence *= 2, sequence) {
        case 6: CHECK(sequence == 6); break;
        default: CHECK(false);
    }
    test_bool_encryption();
    test_scalar_encryption();
    test_string_encryption();
    test_array_encryption();
    test_call_hiding();
    test_hash_agreement();
    test_import_hiding();
    test_inline_std();
    test_control_flow();
#if !CFLOW_ASM_JUNK
    test_compile_time_flow();
#endif
#if defined(__cplusplus) && __cplusplus >= 201703L
    test_if_constexpr();
#endif
    test_misc();

    printf("checks=%d failures=%d\n", checks, failures);
    return failures;
}
