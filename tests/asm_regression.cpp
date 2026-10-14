#include <cstdio>
#define CFLOW_BRANCHING 0
#include "../include/obfusheader.h"

static unsigned failures;
#if OBF_ASM_ENABLED && !defined(OBF_BRK_NONE)
static uint64_t expected(uint64_t x, uint64_t y) {
    return (x ^ (y * 0x9e3779b97f4a7c15ull)) + (x ^ 0xaabbccdd11223344ull)
        + (y + 0x1122334455667788ull) + (x < y ? 13u : 29u);
}

template <int Block>
static NOINLINE uint64_t exercise(uint64_t x, uint64_t y) {
    // In SysV leaf functions these volatile locals may occupy the red zone.
    volatile uint64_t local[] = { x ^ 0xaabbccdd11223344ull, y + 0x1122334455667788ull };
    const bool less = x < y;
    obf::brk::block<Block>::run();
    return (x ^ (y * 0x9e3779b97f4a7c15ull)) + local[0] + local[1] + (less ? 13u : 29u);
}

template <int Block>
static void check_block() {
    for (uint64_t i = 0; i < 4096; ++i) {
        const uint64_t x = i * 0x123456789abcdef1ull;
        const uint64_t y = ~i * 0xfedcba9876543211ull;
        if (exercise<Block>(x, y) != expected(x, y)) ++failures;
    }
}
#endif

int main() {
#if OBF_ASM_ENABLED && !defined(OBF_BRK_NONE)
    check_block<0>(); check_block<1>(); check_block<2>(); check_block<3>();
    check_block<4>(); check_block<5>(); check_block<6>(); check_block<7>();
    check_block<8>(); check_block<9>(); check_block<10>(); check_block<11>();
#endif
    std::printf("asm regression failures=%u\n", failures);
    return failures != 0;
}
