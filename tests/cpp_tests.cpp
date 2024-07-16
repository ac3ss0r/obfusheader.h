#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "..\include\obfusheader.h"

// C++ tests for https://github.com/obfusheader.h

#define CSTD_ASSERT(cond) \
    ((cond)) ? printf("[ASSERT] \"%s\" passed.\n", #cond) : printf("[ASSERT] \"%s\" failed miserably.\n", #cond) && getchar() && *(char*)0xdeadbeef

#if defined(_MSC_VER)
    #define EXPORT __declspec(dllexport)
    #define IMPORT __declspec(dllimport)
#elif defined(__GNUC__) || defined(__clang__) // clang/gcc
    #define EXPORT __attribute__((visibility("default")))
    #define IMPORT
#else // There's nothing we can do
    #define EXPORT
    #define IMPORT
#endif

NOINLINE void set_int(int* a, int param) {
    *a = param;
}

NOINLINE int get_int(int param) {
    return param;
}

extern "C" {

    EXPORT void crackme_graph_test() {
        char password[32];
        printf(OBF("Enter the password: "));
        scanf(OBF("%s"), password); // ah yes, safety
        if (inline_strcmp(password, OBF("secret")) == OBF(0))
            printf(OBF("Congratulations! You have successfully cracked the program.\n"));
        else
            printf(OBF("Sorry, the password is incorrect. Try again!\n"));
    }

    EXPORT void const_encryption_test() {
        // Const encryption tests
        CSTD_ASSERT(OBF(123) == 123);
        CSTD_ASSERT(OBF(9223372036854775807) == 9223372036854775807);
        CSTD_ASSERT(OBF(0x123) == 0x123);
        CSTD_ASSERT(OBF(true) == true);
        CSTD_ASSERT(strcmp(OBF("test"), "test") == 0);
        printf("char*: %s\n"
            "int (dec): %d\n"
            "long long: %llu\n"
            "int (hex): 0x%x\n"
            "boolean: %d\n",
            OBF("test"), OBF(123),
            OBF(9223372036854775807),
            OBF(0x123), OBF(true));
    }

    EXPORT void call_hiding_test() {
        int a = 0;
        CALL(&set_int, &a, 123);
        CSTD_ASSERT(a == 123);
        int b = CALL(&get_int, 123);
        CSTD_ASSERT(b == 123);
    }

    EXPORT void watermark_test() {
        WATERMARK("The quick brown fox jumps over the lazy dog",
                  "The quick brown fox jumps over the lazy dog",
                  "The quick brown fox jumps over the lazy dog");
    }

    EXPORT void call_export_test() {
        #ifdef _WINDOWS
                if (CALL_EXPORT("kernel32.dll", "LoadLibraryA", int(*)(const char*), "user32.dll"))
                    CALL_EXPORT("user32.dll", "MessageBoxA", int(*)(int, const char*, const char*, int), 0, "Real", "Msgbox", 0);
        #elif defined(_LINUX)

        #endif
    }

    EXPORT void indirect_branch_test() {
        INDIRECT_BRANCH;
        WATERMARK("If you see this in the decompiler that means you have unsupported arch compiler or platform.");
    }
}

int main() {
    const_encryption_test();
    indirect_branch_test();
    watermark_test();
    call_hiding_test();
    call_export_test();
    crackme_graph_test();

    getchar();
    return 0;
}