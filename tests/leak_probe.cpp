// Leak probe for obfusheader.h.
//
// A dedicated TU for the plaintext scan: every marker below appears *only* inside
// OBF(), so a hit for it in the produced binary means the payload leaked. The
// self-test cannot be used for this, because CHECK() stringifies its condition with
// #cond and therefore embeds the marker text as a printf argument regardless of the
// encryption.
//
//   g++ -std=c++14 -O2 -I../include leak_probe.cpp -o leak_probe.exe
//   See run_tests.ps1 for the optimization matrix and binary scans.
//
#include <stdio.h>

#include "../include/obfusheader.h"

static volatile int sink;

int main() {
    printf("%s\n", OBF("LEAKPROBE_MARKER_ONE"));
    printf("%s\n", OBF("LEAKPROBE MARKER TWO with spaces and a rather long tail to defeat any short-string heuristic"));
    printf("%s\n", OBF("x"));
    printf("%s\n", OBF(""));
    printf("%ls\n", OBF(L"WIDE_LEAKPROBE_MARKER"));

    sink = OBF(123456789);
    sink = sink + (int)OBF(true);
    sink = sink + OBF(-987654321);
    sink = sink + (int)OBF(0xDEADBEEF);
    sink = sink + (int)OBF(9223372036854775807LL);

    // repeated uses: the same literal encrypted at two different sites
    printf("%s %s\n", OBF("LEAKPROBE_MARKER_ONE"), OBF("LEAKPROBE_MARKER_ONE"));

    return sink == 0 ? 1 : 0;
}
