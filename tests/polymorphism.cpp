#include <cstdio>
#define CFLOW_BRANCHING 0
#include "../include/obfusheader.h"

static unsigned checks;
static unsigned failures;

template <size_t Size, unsigned Site>
static void check_layout() {
    bool seen[Size]{};
    for (size_t i = 0; i < Size; ++i) {
        const size_t physical = obf::payload_layout<Size, Site>::at(i);
        if (physical >= Size || seen[physical]) ++failures;
        else seen[physical] = true;
    }
}

template <class U, int Variant, unsigned Site>
static void check_width() {
    using codec = obf::payload_cipher<U, Variant, Site>;
    static_assert(codec::decode(codec::encode((U)0, (U)0x97), (U)0x97) == 0, "zero roundtrip");
    static_assert(codec::decode(codec::encode((U)~(U)0, (U)0xff), (U)0xff) == (U)~(U)0, "max roundtrip");
    const unsigned count = sizeof(U) == 1 ? 256u : sizeof(U) == 2 ? 65536u : 4096u;
    for (unsigned i = 0; i < count; ++i) {
        const U plain = sizeof(U) <= 2 ? (U)i : (U)((uint64_t)i * 0x9e3779b97f4a7c15ull);
        const unsigned keys = sizeof(U) == 1 ? 256u : 4u;
        for (unsigned k = 0; k < keys; ++k) {
            const U key = sizeof(U) == 1 ? (U)k : obf::key_at<U>(0x87654320u + k, i);
            volatile U encoded = codec::encode(plain, key);
            ++checks;
            if (codec::decode(encoded, key) != plain) ++failures;
        }
    }
}

template <int Variant>
static void check_variant() {
    check_width<uint8_t, Variant, 0x12345678u>();
    check_width<uint16_t, Variant, 0x12345678u>();
    check_width<uint32_t, Variant, 0xdeadbeefu>();
    check_width<uint64_t, Variant, 0xdeadbeefu>();
}

// Stable symbol names for comparing instruction sequences after optimization.
#define SHAPE(n) extern "C" NOINLINE uint64_t poly_decode_##n(uint64_t a, uint64_t key) { \
    return obf::payload_cipher<uint64_t, n, 0x12345678u>::decode(a, key); }
SHAPE(0) SHAPE(1) SHAPE(2) SHAPE(3) SHAPE(4) SHAPE(5) SHAPE(6) SHAPE(7)
#undef SHAPE

int main() {
    check_layout<1, 0>(); check_layout<2, 1>(); check_layout<3, 2>();
    check_layout<6, 3>(); check_layout<16, 0x1234>(); check_layout<31, 0x87654321>();
    check_layout<64, 0xdeadbeef>(); check_layout<257, 0x12345678>();
    using decode_t = uint64_t(*)(uint64_t, uint64_t);
    decode_t volatile shapes[] = { poly_decode_0, poly_decode_1, poly_decode_2, poly_decode_3,
        poly_decode_4, poly_decode_5, poly_decode_6, poly_decode_7 };
    volatile uint64_t shape_sink = 0;
    for (auto& shape : shapes) shape_sink = shape_sink ^ shape(0x123456789abcdef0ull, 0xfedcba9876543210ull);
    (void)shape_sink;
    check_variant<0>(); check_variant<1>(); check_variant<2>(); check_variant<3>();
    check_variant<4>(); check_variant<5>(); check_variant<6>(); check_variant<7>();
    std::printf("polymorphism checks=%u failures=%u\n", checks, failures);
    return failures != 0;
}
