#ifndef OBFUSHEADER_H
#define OBFUSHEADER_H

/*
           __      ____                    __                       __                     __
  ____    / /_    / __/  __  __   _____   / /_   ___   ____ _  ____/ /  ___    _____      / /_
 / __ \  / __ \  / /_   / / / /  / ___/  / __ \ / _ \ / __ `/ / __  /  / _ \  / ___/     / __ \
/ /_/ / / /_/ / / __/  / /_/ /  (__  )  / / / //  __// /_/ / / /_/ /  /  __/ / /     _  / / / /
\____/ /_.___/ /_/     \__,_/  /____/  /_/ /_/ \___/ \__,_/  \__,_/   \___/ /_/     (_)/_/ /_/

  Compile-time obfuscation for C/C++ (C++14 and newer) with no external dependencies.
  https://github.com/ac3ss0r/obfusheader.h

  Every protection lives in its own section so it can be read, ported or disabled on its
  own. Section 15 must stay last: it redefines the C++ keywords used by the control flow
  mutation, which also affects any header included after this one.

    1   Configuration           every knob, all overridable with -D or a #define
    2   Target detection        compiler / instruction set / operating system
    3   Core primitives         inlining, sections, casts, warning control
    4   Compile-time entropy    RND(), per-build salt, constexpr hashing
    5   Opaque predicates       volatile constant pool, polymorphic XOR algebra
    6   Assembly junk           polymorphic STACKBRK blocks (x86, x64, ARM64, ARM32)
    7   Control flow            indirect branching, cflow gates, hard faults
    8   Metaprogramming         the frozen subset of <type_traits> this header needs
    9   Constant encryption     string/decimal vaults with hidden references
    10  Call hiding             shuffled function pointer tables
    11  Import hiding           PEB walking (Windows) / ELF parsing (Linux)
    12  Watermarking            messages for crackers that survive optimization
    13  Fake signatures         detector bait for VMProtect/Themida/Denuvo
    14  Inline stdlib           libc string routines, so nothing hookable is imported
    15  Keyword mutation        if/else/for/while/switch/return -- keep last
*/

/* =============================================================================
 * 1. CONFIGURATION
 *
 * Nothing here needs to be edited in place: every option can be set before the
 * include, or on the command line per translation unit, e.g.
 *
 *   #define CFLOW_BRANCHING 0     // a file full of constexpr code
 *   #include "obfusheader.h"
 *
 * or  g++ -DVAULT_SLOTS=6 -DCFLOW_ASM_JUNK=0 ...
 * ============================================================================= */

    // Encryption modes for CONST_ENCRYPT_MODE.
    #define OBF_MODE_NORMAL      0 // the payload is decrypted into the stack of each call
    #define OBF_MODE_THREADLOCAL 1 // one decrypted copy is cached per thread

    #ifndef NORMAL
        #define NORMAL OBF_MODE_NORMAL      // legacy spelling
    #endif
    #ifndef THREADLOCAL
        #define THREADLOCAL OBF_MODE_THREADLOCAL // legacy spelling
    #endif

    // Import resolvers for CALL_EXPORT. The manual backends never reference the loader
    // APIs, so neither the import table nor any symbol name string identifies the call.
    #define OBF_RESOLVER_AUTO   0 // manual (PEB / ELF), API fallback if it fails
    #define OBF_RESOLVER_MANUAL 1 // manual only, no GetProcAddress / dlsym at all
    #define OBF_RESOLVER_API    2 // legacy GetProcAddress / dlsym lookup

    // ---- compile-time constant encryption (C++ only) ----
    #ifndef CONST_ENCRYPTION
        #define CONST_ENCRYPTION 1     // encrypt literals passed to OBF()/MAKEOBF()
    #endif
    #ifndef CONST_ENCRYPT_MODE
        #define CONST_ENCRYPT_MODE NORMAL
    #endif
    #ifndef VAULT_SLOTS
        #define VAULT_SLOTS 4          // decoy buffers stored next to every payload
    #endif
    #ifndef VAULT_CHECK
        #define VAULT_CHECK 1          // verify the decrypted payload against a
                                       // compile-time checksum of the original
    #endif

    // ---- control flow ----
    #ifndef CFLOW_BRANCHING
        #define CFLOW_BRANCHING 1      // mutate if/else/for/while/switch/return
    #endif
    #ifndef CFLOW_CONST_DECRYPTION
        #define CFLOW_CONST_DECRYPTION 1 // fake branches inside the decryptor loop
    #endif
    #ifndef CFLOW_ASM_JUNK
        #define CFLOW_ASM_JUNK 1       // 0 keeps every cflow construct legal inside
                                       // constexpr code and forbids inline asm in it
    #endif
    // Individual keywords can be left out of the mutation while the rest stays on.
    #ifndef CFLOW_IF
        #define CFLOW_IF CFLOW_BRANCHING
    #endif
    #ifndef CFLOW_ELSE
        #define CFLOW_ELSE CFLOW_BRANCHING
    #endif
    #ifndef CFLOW_FOR
        #define CFLOW_FOR CFLOW_BRANCHING
    #endif
    #ifndef CFLOW_WHILE
        #define CFLOW_WHILE CFLOW_BRANCHING
    #endif
    #ifndef CFLOW_SWITCH
        #define CFLOW_SWITCH CFLOW_BRANCHING
    #endif
    #ifndef CFLOW_RETURN
        #define CFLOW_RETURN CFLOW_BRANCHING
    #endif
    #ifndef INDIRECT_BRANCHING
        #define INDIRECT_BRANCHING 1   // opaque conditional jumps in the cflow gates
    #endif

    // ---- assembly junk ----
    // Named apart from the ASM_JUNK()/STACKBRK() macros below, which expand to code.
    #ifndef JUNK_ASM
        #define JUNK_ASM 1             // polymorphic instructions inside executed code
    #endif
    #ifndef JUNK_TRAP
        #define JUNK_TRAP 1            // unreachable breakpoint/undefined-opcode bait
    #endif

    // ---- calls & imports ----
    #ifndef CALL_SLOTS
        #define CALL_SLOTS 10          // entries in a hidden call table (2..10)
    #endif
    #ifndef IMPORT_RESOLVER
        #define IMPORT_RESOLVER OBF_RESOLVER_AUTO
    #endif
    #ifndef IMPORT_CACHE
        #define IMPORT_CACHE 1         // cache resolved imports XOR-masked in .data
    #endif

    // ---- misc ----
    #ifndef FAKE_SIGNATURES
        #define FAKE_SIGNATURES 0      // protector bait for Detect-It-Easy & friends
    #endif
    #ifndef INLINE_STD
        #define INLINE_STD 1           // the inline std string routines (section 14)
    #endif
    #ifndef KERNEL_MODE
        #define KERNEL_MODE 0          // do not pull in <windows.h> / <dlfcn.h>
    #endif
    #ifndef WATERMARKING
        #define WATERMARKING 1         // named apart from the WATERMARK() macro
    #endif

    // ---- configuration sanity ----
    #if CONST_ENCRYPT_MODE != OBF_MODE_NORMAL && CONST_ENCRYPT_MODE != OBF_MODE_THREADLOCAL
        #error "obfusheader: CONST_ENCRYPT_MODE must be NORMAL or THREADLOCAL"
    #endif
    #if VAULT_SLOTS < 1 || VAULT_SLOTS > 8
        #error "obfusheader: VAULT_SLOTS must be between 1 and 8"
    #endif
    #if CALL_SLOTS < 2 || CALL_SLOTS > 10
        #error "obfusheader: CALL_SLOTS must be between 2 and 10"
    #endif
    #if (CFLOW_IF || CFLOW_ELSE || CFLOW_FOR || CFLOW_WHILE || CFLOW_SWITCH || CFLOW_RETURN) && !CFLOW_BRANCHING
        #error "obfusheader: keyword mutation needs CFLOW_BRANCHING, set CFLOW_BRANCHING to 1 or the keywords to 0"
    #endif
    #if !CONST_ENCRYPTION && (VAULT_SLOTS || VAULT_CHECK)
        // These options simply have nothing to protect, which is not an error.
    #endif

/* =============================================================================
 * 2. TARGET DETECTION
 * ============================================================================= */

    #if defined(_MSC_VER) && !defined(__clang__) && !defined(__llvm__)
        #define OBF_MSVC 1 // clang re-defines _MSC_VER for MSVC-compatible builds
        #define OBF_GNU  0
    #elif defined(__GNUC__) || defined(__clang__) || defined(__llvm__)
        #define OBF_MSVC 0
        #define OBF_GNU  1
    #elif defined(__TINYC__)
        #define OBF_MSVC 0
        #define OBF_GNU  0
    #else
        #define OBF_MSVC 0
        #define OBF_GNU  0
    #endif

    #if defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
        #define OBF_X86 1
        #define OBF_ARM 0
        #define OBF_64BIT 0
    #elif defined(__x86_64__) || defined(_M_X64) || defined(x86_64)
        #define OBF_X86 1
        #define OBF_ARM 0
        #define OBF_64BIT 1
    #elif defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC) || defined(__arm64__)
        #define OBF_X86 0
        #define OBF_ARM 1
        #define OBF_64BIT 1
    #elif defined(__arm__) || defined(_M_ARM) || defined(__thumb__)
        #define OBF_X86 0
        #define OBF_ARM 1
        #define OBF_64BIT 0
    #else
        #define OBF_X86 0
        #define OBF_ARM 0
        #define OBF_64BIT 0
    #endif

    #if defined(_WIN64) || defined(WIN64) || defined(_WIN32) || defined(WIN32) || defined(__WIN32__) || defined(__NT__)
        #define OBF_WINDOWS 1
        #define OBF_LINUX   0
        #define OBF_APPLE   0
    #elif defined(__linux__) || defined(__ANDROID__)
        #define OBF_WINDOWS 0
        #define OBF_LINUX   1
        #define OBF_APPLE   0
    #elif defined(__APPLE__)
        #define OBF_WINDOWS 0
        #define OBF_LINUX   0
        #define OBF_APPLE   1
    #else
        #define OBF_WINDOWS 0
        #define OBF_LINUX   0
        #define OBF_APPLE   0
    #endif

    // Legacy spellings kept for existing code that tests these with #ifdef.
    #if OBF_MSVC && !defined(_MSVC)
        #define _MSVC
    #endif
    #if OBF_GNU && !defined(_GNUC)
        #define _GNUC
    #endif
    #if OBF_WINDOWS && !defined(_WINDOWS)
        #define _WINDOWS
    #endif
    #if OBF_LINUX && !defined(_LINUX)
        #define _LINUX
    #endif
    #if OBF_APPLE && !defined(_APPLE)
        #define _APPLE
    #endif
    #if !OBF_X86 && !OBF_ARM
        // Unknown target: everything except the data protection degrades to nothing.
    #endif
    #if defined(__x86_64__) || defined(_M_X64)
        #if !defined(x86_64) && !defined(__x86_64)
            #define x86_64
        #endif
    #elif defined(i386) || defined(__i386__) || defined(_M_IX86)
        #ifndef x86_32
            #define x86_32
        #endif
    #endif

    #if defined(__TINYC__)
        #error "obfusheader does not support TCC. Consider https://github.com/DosX-dev/obfus.h instead"
    #elif !defined(OBF_UNSUPPORTED) && OBF_MSVC == 0 && OBF_GNU == 0
        #error "obfusheader: your compiler is most likely not supported. Define OBF_UNSUPPORTED if you are sure it is."
    #endif

/* =============================================================================
 * 3. CORE PRIMITIVES
 * ============================================================================= */

    #include <stdint.h>  // exact width integers for the cipher, PE and ELF layouts
    #include <stddef.h>  // size_t

    #if OBF_MSVC
        #pragma warning(push)
        // 4996 CRT names     4100 unreferenced param   4127 constant condition
        // 4505 unreferenced static  4702 unreachable   4102 unreachable label
        // 4244/4267 narrowing  4310 cast truncates const  4018 signed compare
        // 4191 asm cast       4312 pointer cast      4701 possibly uninit
        #pragma warning(disable : 4996 4100 4127 4505 4702 4102 4244 4267 4310 4018 4191 4312 4701 4189 4706)
    #elif OBF_GNU
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wunused-function"
        #pragma GCC diagnostic ignored "-Wunused-label"
        #pragma GCC diagnostic ignored "-Wunknown-pragmas"
        #if defined(__cplusplus)
            #pragma GCC diagnostic ignored "-Winvalid-constexpr"
        #endif
    #endif

    #if OBF_MSVC
        #include <intrin.h> // __readgsqword/__readfsdword for the PEB walk, __nop, __debugbreak
    #endif

    // Without forceinline the compiler mostly ignores the inline hint and the
    // obfuscation ends up as real calls instead of inlined junk.
    #if OBF_MSVC
        #define INLINE __forceinline
    #else
        #define INLINE __attribute__((always_inline))
    #endif

    // The opposite: keeps a function from being folded into its caller, so the
    // opaque predicates inside it stay opaque at the call site.
    #if OBF_MSVC
        #define NOINLINE __declspec(noinline)
    #else
        #define NOINLINE __attribute__((noinline))
    #endif

    #if OBF_MSVC
        #define SECTION(x) __declspec(allocate(x))
    #else
        #define SECTION(x) __attribute__((section(x)))
    #endif

    #ifdef __cplusplus
        #define CAST(T, v)  static_cast<T>(v)
        #define RCAST(T, v) reinterpret_cast<T>(v)
        #define CCAST(T, v) const_cast<T>(v)
    #else
        #define CAST(T, v)  ((T)(v))
        #define RCAST(T, v) ((T)(uintptr_t)(v))
        #define CCAST(T, v) ((T)(uintptr_t)(v))
    #endif

    // Forces the argument to be evaluated, unlike sizeof.
    #define OBF_UNUSED(x) ((void)(x))

    // Internal snapshots of the switches whose names double as macro names, so a
    // later "#define ASM_JUNK some_code" can never end up inside a #if expression.
    #if JUNK_ASM
        #define OBF_ASM_ENABLED 1
    #else
        #define OBF_ASM_ENABLED 0
    #endif
    #if JUNK_TRAP
        #define OBF_TRAP_ENABLED 1
    #else
        #define OBF_TRAP_ENABLED 0
    #endif
    #if INDIRECT_BRANCHING
        #define OBF_IBRANCH_ENABLED 1
    #else
        #define OBF_IBRANCH_ENABLED 0
    #endif

    // A pointer-sized value that is wide enough to hold any function or object address
    // on every supported target.
    #define OBF_UINT uintptr_t

    // The gates in section 7 are deliberately 64 bit rather than pointer sized: on a
    // 32 bit target a pointer-sized gate truncates the high half of a 64 bit key, and
    // the payload then decrypts to the wrong value.
    #define OBF_CF_T unsigned long long

/* =============================================================================
 * 4. COMPILE-TIME ENTROPY
 *
 * __COUNTER__ + __LINE__ + __TIME__ make every expansion of RND() different, which
 * is what makes the junk below polymorphic instead of a copy of the same block.
 * __TIME__ is reduced to a sum of its characters so no "HH:MM:SS" string survives.
 * ============================================================================= */

    #ifdef __cplusplus
        static constexpr int OBF_TIME_HASH = __TIME__[0] + __TIME__[1] + __TIME__[3]
                                           + __TIME__[4] + __TIME__[6] + __TIME__[7];
        #define OBF_TIME_MIX ((unsigned)OBF_TIME_HASH * 0x9E3779B9u)
    #else
        // No constexpr in C, so __TIME__ would end up embedded in the binary.
        #define OBF_TIME_MIX 0u
    #endif

    // A 32 bit avalanche per expansion site: consecutive __COUNTER__ values are
    // multiplied apart and folded again so small ranges stay evenly spread.
    #define OBF_ENTROPY                                                                 \
        ((unsigned)((unsigned)(__COUNTER__ * 2654435761u) ^ ((unsigned)__LINE__ * 40503u) ^ OBF_TIME_MIX) * 2246822519u)

    #define RND(Min, Max) ((Min) + (int)(OBF_ENTROPY % (unsigned)(((Max) - (Min)) + 1)))
    #define OBF_RAND RND(1, 10) // legacy alias used by the predicate pool

    // Everything derived from names is salted per build, so a hash of a known API
    // string cannot be looked up in a pre-computed table.
    #define OBF_BUILD_SALT ((unsigned)(OBF_TIME_MIX ^ 0x5BF03635u))

    #ifdef __cplusplus
    namespace obf {

        // Per-build mixing constants.
        namespace k {

            INLINE constexpr unsigned long long draw(unsigned i) {
                unsigned long long h = (unsigned long long)OBF_BUILD_SALT * 0xD1B54A32D192ED03ull
                                     + (unsigned long long)i * 0xA95317C4DEA7883Full;
                h ^= h >> 31;
                h *= 0x94D049BB133111EBull;
                return h ^ (h >> 29);
            }

            INLINE constexpr unsigned word(unsigned i) { return (unsigned)draw(i); }

            INLINE constexpr unsigned mul32(unsigned i) {
                return (unsigned)((draw(i) | 0x81800001ull) & 0xFFFDFFFFull);
            }

            INLINE constexpr unsigned long long mul64(unsigned i) {
                return (draw(i) | 0x8180000000000001ull) & 0xFFFDFFFFFFFFFFFFull;
            }

            INLINE constexpr unsigned byte(unsigned i) {
                return (unsigned)(draw(i) & 0xFFull) | 1u;
            }

            INLINE constexpr unsigned shr(unsigned i, unsigned lo, unsigned hi) {
                return lo + (unsigned)(draw(i) % (unsigned long long)(hi - lo + 1));
            }
        }

        // Indices into draw(); grouping them here keeps every user of one constant
        // on the same value, which matters because the compile-time hash and the
        // run-time hash of a name have to agree or import hiding resolves nothing.
        #define OBF_K_SEED   1 // hash seed
        #define OBF_K_MUL    2 // hash step multiplier
        #define OBF_K_SALT   3 // final salt multiplier
        #define OBF_K_STRIDE 4 // key schedule index stride
        #define OBF_K_KA     5 // key schedule mixers
        #define OBF_K_KB     6
        #define OBF_K_KC     7
        #define OBF_K_S1     8 // key schedule shifts
        #define OBF_K_S2     9
        #define OBF_K_D1     10 // decoy row mixer
        #define OBF_K_D2     11
        #define OBF_K_SLOT   12 // masked slot/index multipliers
        #define OBF_K_DECOY  13 // call table decoy picker

        // One step of the name hash: multiply-xor over a byte. hash_wide() and
        // hash_runtime() feed this same function, so the algorithm lives in one place
        // and its constants are emitted once instead of four times. Named apart from
        // the vault's own checksum step, which must agree with itself but not with this.
        INLINE constexpr unsigned hash_feed(unsigned h, unsigned c) {
            return (h ^ c) * k::mul32(OBF_K_MUL);
        }

        // Computed at compile time for literals and at run time against the export
        // tables of the loaded modules, so no API name has to be stored. The shape is
        // multiply-xor like FNV-1a, the numbers are this build's own.
        INLINE constexpr unsigned hash_fnv(const char* s) {
            unsigned h = k::mul32(OBF_K_SEED);
            for (; *s != 0; ++s)
                h = hash_feed(h, (unsigned)(unsigned char)*s);
            return h;
        }

        // Same, case insensitive: module names are compared case insensitively.
        INLINE constexpr unsigned hash_fnv_lower(const char* s) {
            unsigned h = k::mul32(OBF_K_SEED);
            for (; *s != 0; ++s) {
                unsigned c = (unsigned)(unsigned char)*s;
                if (c >= 'A' && c <= 'Z') c = c + 32u;
                h = hash_feed(h, c);
            }
            return h;
        }

        // ELF's own hash, needed to index the GNU/SYSV hash tables of a shared object.
        // This one has to stay exactly as the loader computes it, constants included.
        INLINE constexpr unsigned hash_elf(const char* s) {
            unsigned h = 0u, g = 0u;
            for (; *s != 0; ++s) {
                h = (h << 4) + (unsigned)(unsigned char)*s;
                g = h & 0xf0000000u;
                if (g != 0) {
                    h ^= g >> 24;
                    h &= ~g;
                }
            }
            return h;
        }

        INLINE constexpr unsigned hash_salt(unsigned h) {
            return (h ^ OBF_BUILD_SALT) * k::mul32(OBF_K_SALT);
        }
    }
    #define OBF_HASH(s)        obf::hash_salt(obf::hash_fnv(s))
    #define OBF_HASH_LOWER(s)  obf::hash_salt(obf::hash_fnv_lower(s))
    // The unsalted ELF hash: the loader's own hash tables are indexed by it, so it has
    // to stay plain, while OBF_HASH() is what the names are verified against.
    #define OBF_ELF_HASH(s)    obf::hash_elf(s)
    #endif

/* =============================================================================
 * 5. OPAQUE PREDICATES & XOR ALGEBRA
 *
 * Two families on purpose:
 *   - the volatile pool below makes the *runtime* predicates cost a real load each,
 *     so a decompiler cannot fold the fake branches away;
 *   - section 7 adds a constexpr-only gate that reads nothing volatile, which is
 *     what makes cflow legal inside compile-time code.
 * ============================================================================= */

    #if OBF_MSVC
        #include <intrin.h> // __readgsqword / __readfsdword for the PEB walk, __nop, __debugbreak
    #endif

    // Opaque predicate values. obf_psel_a() is always non zero and
    // obf_psel_b() always zero, but neither is a visible constant: they are
    // rebuilt from a volatile pool through noinline helpers, which is what keeps a
    // decompiler from folding the fake branches away.
    //
    // With CFLOW_ASM_JUNK=0 the pool is not used at all and the predicates become
    // plain constants, which is what makes the cflow legal inside constexpr code.
    #if CFLOW_ASM_JUNK
        // The pool used to be obf_pool_0 = 0 .. obf_pool_9 = 9 sitting next to an
        // 'a'..'z' run of tag bytes. A consecutive byte run is the easiest pattern in
        // this file to match on, and every predicate built on it hard-coded the values,
        // so changing one number broke the other. The bytes are now drawn per
        // expansion site from the compile-time entropy, which makes them different in
        // every translation unit and - together with __TIME__ in the C++ mix - in every
        // build, and the predicates below are identities that hold for *any* contents.
        static volatile unsigned char obf_vb_0 = (unsigned char)RND(1, 255);
        static volatile unsigned char obf_vb_1 = (unsigned char)RND(1, 255);
        static volatile unsigned char obf_vb_2 = (unsigned char)RND(1, 255);
        static volatile unsigned char obf_vb_3 = (unsigned char)RND(1, 255);
        static volatile unsigned char obf_vb_4 = (unsigned char)RND(1, 255);
        static volatile unsigned char obf_vb_5 = (unsigned char)RND(1, 255);
        static volatile unsigned char obf_vb_6 = (unsigned char)RND(1, 255);
        static volatile unsigned char obf_vb_7 = (unsigned char)RND(1, 255);
        static volatile unsigned char obf_vb_8 = (unsigned char)RND(1, 255);
        static volatile unsigned char obf_vb_9 = (unsigned char)RND(1, 255);

        // Two reads of a volatile object may not be merged, so the optimizer has to
        // keep both loads and cannot prove the comparison. The value does not matter:
        // a total order makes (a != b) + (a == b) exactly one, and (a < b) & (b < a)
        // exactly zero, for every pair a program can actually produce. Neither form
        // contains a constant, and each reads a different pair of cells, so no two
        // predicates disassemble the same way.
        static NOINLINE unsigned obf_psel_a() {
            const unsigned a = obf_vb_3, b = obf_vb_5;
            return (unsigned)(a != b) + (unsigned)(a == b);
        }
        static NOINLINE unsigned obf_psel_b() {
            const unsigned a = obf_vb_2, b = obf_vb_7;
            return (unsigned)(a < b) & (unsigned)(b < a);
        }

        #define OBF_PRED_TRUE  (obf_psel_a())
        #define OBF_PRED_FALSE (obf_psel_b())
    #else
        #define OBF_PRED_TRUE  1u
        #define OBF_PRED_FALSE 0u
    #endif

    // Variadic on purpose: a block of code contains commas, which would otherwise be
    // read as extra arguments.
    #define BLOCK_COND(cond, ...) if (cond) { __VA_ARGS__ ; }
    #define BLOCK_TRUE(...)  BLOCK_COND(OBF_PRED_TRUE, __VA_ARGS__)
    #define BLOCK_FALSE(...) BLOCK_COND(OBF_PRED_FALSE, __VA_ARGS__)

    // XOR without the ^ operator, so the cipher is not a single recognizable opcode.
    #define XOR(x, y) ((x) + (y) - (2 * ((x) & (y))))

    #ifdef __cplusplus
    namespace obf {

        // Every variant computes a ^ b; the choice is made per instantiation site, so
        // two identical strings decrypt through structurally different code.
        template <class U, int Variant>
        struct cipher {
            static INLINE constexpr U mix(U a, U b) { return (U)(a + b - 2 * (a & b)); }
        };
        template <class U>
        struct cipher<U, 1> {
            static INLINE constexpr U mix(U a, U b) { return (U)((a | b) - (a & b)); }
        };
        template <class U>
        struct cipher<U, 2> {
            static INLINE constexpr U mix(U a, U b) { return (U)((a & ~b) | (b & ~a)); }
        };
        template <class U>
        struct cipher<U, 3> {
            static INLINE constexpr U mix(U a, U b) { return (U)(a ^ b); }
        };
        template <class U>
        struct cipher<U, 4> {
            static INLINE constexpr U mix(U a, U b) { return (U)(((a | b) - (a & b)) + 0 * a); }
        };

        #define OBF_CIPHER_VARIANTS 5

        // Unsigned integer of exactly N bytes; the cipher always works on the widest
        // unsigned type of the payload's size, which is what keeps bool and char keys
        // from losing bits (see the static asserts below).
        template <size_t N>
        struct uint_of;
        template <> struct uint_of<1> { typedef uint8_t  type; };
        template <> struct uint_of<2> { typedef uint16_t type; };
        template <> struct uint_of<4> { typedef uint32_t type; };
        template <> struct uint_of<8> { typedef uint64_t type; };

        template <class T>
        struct cipher_of { typedef typename uint_of<sizeof(T)>::type type; };

        // Key schedule: one full width key per element instead of the classic
        // (key + index), so a long string does not walk up into the next key byte.
        // The mixers and the shift widths come from the per-build constants: this runs
        // inside the decryptor at run time, so its numbers are in the object file and
        // must not be the published splitmix ones.
        template <class U>
        INLINE constexpr U key_at(unsigned char base, unsigned index) {
            const unsigned char raw = (unsigned char)(base + (unsigned char)(index * k::byte(OBF_K_STRIDE)));
            unsigned long long h = (unsigned long long)raw * k::mul64(OBF_K_KA) + (unsigned long long)index * k::mul64(OBF_K_KB);
            h ^= h >> k::shr(OBF_K_S1, 29u, 40u); h *= k::mul64(OBF_K_KC); h ^= h >> k::shr(OBF_K_S2, 25u, 36u);
            return (U)h;
        }

        // The cipher must be its own inverse, for every width and every variant.
        #define OBF_CIPHER_INVOLUTIVE(U, V) \
            (cipher<U, V>::mix(cipher<U, V>::mix((U)0xC3u, (U)0x97u), (U)0x97u) == (U)0xC3u \
             && cipher<U, V>::mix(cipher<U, V>::mix((U)0x00u, (U)0xFFu), (U)0xFFu) == (U)0x00u)

        static_assert(OBF_CIPHER_INVOLUTIVE(uint8_t, 0), "cipher variant 0 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint8_t, 1), "cipher variant 1 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint8_t, 2), "cipher variant 2 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint8_t, 3), "cipher variant 3 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint8_t, 4), "cipher variant 4 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint16_t, 0), "16 bit cipher variant 0 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint16_t, 2), "16 bit cipher variant 2 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint32_t, 0), "32 bit cipher variant 0 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint32_t, 1), "32 bit cipher variant 1 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint32_t, 2), "32 bit cipher variant 2 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint64_t, 0), "64 bit cipher variant 0 must be involutive");
        static_assert(OBF_CIPHER_INVOLUTIVE(uint64_t, 2), "64 bit cipher variant 2 must be involutive");
        #undef OBF_CIPHER_INVOLUTIVE

        // A bool/char payload must not lose the key: this is the regression that the
        // old "#define true 1" workaround was papering over.
        static_assert(cipher<uint8_t, 0>::mix((uint8_t)1u, key_at<uint8_t>((unsigned char)0x80u, 0u)) != 1u,
                      "bool payload must actually change under the key");
    }
    #endif

/* =============================================================================
 * 6. ASSEMBLY JUNK
 *
 * A library of tiny instruction blocks plus a compile-time combiner, so every
 * expansion of ASM_JUNK()/STACKBRK() emits a different mix. The choice is made
 * through template arguments, which means it is decided per expansion site and
 * costs nothing at run time.
 *
 * Two families:
 *   OBF_BRK_n  executed. Every instruction here is a no-op, or works on a scratch
 *              register the compiler owns via "+r", so program state never changes.
 *   OBF_TRAP_n never executed: they sit inside BLOCK_FALSE, whose condition is a
 *              volatile read the optimizer is not allowed to fold away. They put
 *              int3/ud2/brk/bkpt encodings into the binary as bait without ever
 *              running.
 * ============================================================================= */

    #define OBF_BRK_VARIANTS 12
    #define OBF_TRAP_VARIANTS 6

    // Arithmetic stand-in for targets without inline asm: volatile forces the loads and
    // stores to stay, the balanced pairs make it semantically a no-op. The operands are
    // drawn per expansion site and bound to a local, because a second RND() inside the
    // same pair would return a different value and the pair would stop cancelling.
    #define OBF_BRK_ARITH(seed)                                                       \
        do {                                                                          \
            volatile OBF_UINT obf_ar_ = (OBF_UINT)(seed);                             \
            const OBF_UINT obf_ar_k_ = (OBF_UINT)RND(1, 0x3FFFFFFF);                  \
            const OBF_UINT obf_ar_d_ = (OBF_UINT)RND(1, 0x3F);                         \
            obf_ar_ ^= obf_ar_k_; obf_ar_ ^= obf_ar_k_;                                \
            obf_ar_ += obf_ar_d_; obf_ar_ -= obf_ar_d_;                                \
            (void)obf_ar_; (void)obf_ar_k_; (void)obf_ar_d_;                           \
        } while (0)

    #if !OBF_ASM_ENABLED || (!OBF_X86 && !OBF_ARM)
        #define OBF_BRK_NONE 1
    #elif OBF_GNU && OBF_X86
        #define OBF_ASM_PLAIN(text) __asm__ __volatile__(text)
        #define OBF_ASM_RW(insn)    do { OBF_UINT obf_j_ = 0; __asm__ __volatile__(insn : "+r"(obf_j_)); (void)obf_j_; } while (0)

        #define OBF_BRK_0  OBF_ASM_PLAIN("nop")
        #define OBF_BRK_1  OBF_ASM_PLAIN("xchgw %ax, %ax")
        #define OBF_BRK_2  do { OBF_ASM_RW("lea 0x10(%0), %0"); OBF_ASM_RW("sub $0x10, %0"); } while (0)
        #define OBF_BRK_3  do { OBF_ASM_RW("not %0"); OBF_ASM_RW("not %0"); } while (0)
        #define OBF_BRK_4  OBF_ASM_PLAIN("pushf" "\n\t" "popf")
        #define OBF_BRK_5  do { OBF_ASM_RW("bswap %0"); OBF_ASM_RW("bswap %0"); } while (0)
        #define OBF_BRK_6  OBF_ASM_PLAIN("std" "\n\t" "cld")
        #define OBF_BRK_7  OBF_ASM_PLAIN(".byte 0x0f,0x1f,0x00")
        #define OBF_BRK_8  do { OBF_ASM_RW("lea 0x2(%0), %0"); OBF_ASM_RW("lea -0x2(%0), %0"); } while (0)
        #define OBF_BRK_9  OBF_ASM_PLAIN(".byte 0x64,0x90")
        #define OBF_BRK_10 OBF_ASM_PLAIN("lahf" "\n\t" "sahf")
        #define OBF_BRK_11 do { OBF_ASM_RW("mov %0, %0"); OBF_ASM_RW("or $0x0, %0"); } while (0)

        #define OBF_TRAP_0 BLOCK_FALSE(OBF_ASM_PLAIN("int3"))
        #define OBF_TRAP_1 BLOCK_FALSE(OBF_ASM_PLAIN("ud2"))
        #define OBF_TRAP_2 BLOCK_FALSE(OBF_ASM_PLAIN(".byte 0x0f,0xff"))
        #define OBF_TRAP_3 BLOCK_FALSE(OBF_ASM_PLAIN(".byte 0xf1"))
        #define OBF_TRAP_4 BLOCK_FALSE(OBF_ASM_PLAIN(".byte 0xff,0xff"))
        #define OBF_TRAP_5 BLOCK_FALSE(OBF_ASM_PLAIN(".byte 0x00,0x00"))
    #elif OBF_GNU && OBF_ARM && OBF_64BIT
        // aarch64
        #define OBF_ASM_PLAIN(text) __asm__ __volatile__(text)
        #define OBF_ASM_RW(insn)    do { OBF_UINT obf_j_ = 0; __asm__ __volatile__(insn : "+r"(obf_j_)); (void)obf_j_; } while (0)

        #define OBF_BRK_0  OBF_ASM_PLAIN("nop")
        #define OBF_BRK_1  OBF_ASM_PLAIN("yield")
        #define OBF_BRK_2  OBF_ASM_PLAIN("hint #32")
        #define OBF_BRK_3  do { OBF_ASM_RW("mov %0, %0"); OBF_ASM_RW("add %0, %0, #16"); OBF_ASM_RW("sub %0, %0, #16"); } while (0)
        #define OBF_BRK_4  do { OBF_ASM_RW("orr %0, %0, %0"); OBF_ASM_RW("eon %0, %0, %0"); OBF_ASM_RW("eon %0, %0, %0"); } while (0)
        #define OBF_BRK_5  OBF_ASM_PLAIN(".inst 0xd503201f")
        #define OBF_BRK_6  do { OBF_ASM_RW("rev %0, %0"); OBF_ASM_RW("rev %0, %0"); } while (0)
        #define OBF_BRK_7  do { OBF_ASM_RW("rbit %0, %0"); OBF_ASM_RW("rbit %0, %0"); } while (0)
        #define OBF_BRK_8  OBF_ASM_PLAIN("csdb")
        #define OBF_BRK_9  do { OBF_ASM_RW("cls %0, %0"); OBF_ASM_RW("clz %0, %0"); } while (0)
        #define OBF_BRK_10 OBF_ASM_PLAIN(".word 0xd503203f")
        #define OBF_BRK_11 do { OBF_ASM_RW("add %0, %0, #1"); OBF_ASM_RW("sub %0, %0, #1"); } while (0)

        #define OBF_TRAP_0 BLOCK_FALSE(OBF_ASM_PLAIN("brk #1"))
        #define OBF_TRAP_1 BLOCK_FALSE(OBF_ASM_PLAIN("brk #0"))
        #define OBF_TRAP_2 BLOCK_FALSE(OBF_ASM_PLAIN("brk #0x1234"))
        #define OBF_TRAP_3 BLOCK_FALSE(OBF_ASM_PLAIN(".inst 0x00000000"))
        #define OBF_TRAP_4 BLOCK_FALSE(OBF_ASM_PLAIN(".word 0x00000000"))
        #define OBF_TRAP_5 BLOCK_FALSE(OBF_ASM_PLAIN(".inst 0xd4200000"))
    #elif OBF_GNU && OBF_ARM
        // arm32 / thumb2: "l" keeps the scratch in the low registers, and only
        // encodings that exist in both ISA states are used.
        #define OBF_ASM_PLAIN(text) __asm__ __volatile__(text)
        #define OBF_ASM_RW(insn)    do { unsigned obf_j_ = 0; __asm__ __volatile__(insn : "+l"(obf_j_)); (void)obf_j_; } while (0)

        #define OBF_BRK_0  OBF_ASM_PLAIN("nop")
        #define OBF_BRK_1  OBF_ASM_PLAIN("yield")
        #define OBF_BRK_2  do { OBF_ASM_RW("movs %0, %0"); OBF_ASM_RW("orr %0, %0, #0"); } while (0)
        #define OBF_BRK_3  do { OBF_ASM_RW("mvn %0, %0"); OBF_ASM_RW("mvn %0, %0"); } while (0)
        #define OBF_BRK_4  do { OBF_ASM_RW("rev %0, %0"); OBF_ASM_RW("rev %0, %0"); } while (0)
        #define OBF_BRK_5  do { OBF_ASM_RW("rbit %0, %0"); OBF_ASM_RW("rbit %0, %0"); } while (0)
        #define OBF_BRK_6  do { OBF_ASM_RW("add %0, %0, #8"); OBF_ASM_RW("sub %0, %0, #8"); } while (0)
        #define OBF_BRK_7  do { OBF_ASM_RW("tst %0, #1"); OBF_ASM_RW("add %0, %0, #0"); } while (0)
        #define OBF_BRK_8  do { OBF_ASM_RW("add %0, %0, #1"); OBF_ASM_RW("sub %0, %0, #1"); } while (0)
        #define OBF_BRK_9  OBF_ASM_PLAIN("nop")
        #define OBF_BRK_10 do { OBF_ASM_RW("mov %0, %0"); } while (0)
        #define OBF_BRK_11 do { OBF_ASM_RW("orr %0, %0, #1"); OBF_ASM_RW("eor %0, %0, #1"); } while (0)

        #define OBF_TRAP_0 BLOCK_FALSE(OBF_ASM_PLAIN("bkpt #1"))
        #define OBF_TRAP_1 BLOCK_FALSE(OBF_ASM_PLAIN("bkpt #0"))
        #define OBF_TRAP_2 BLOCK_FALSE(OBF_ASM_PLAIN("udf #16"))
        #define OBF_TRAP_3 BLOCK_FALSE(OBF_ASM_PLAIN(".word 0xe7f001f0"))
        #define OBF_TRAP_4 BLOCK_FALSE(OBF_ASM_PLAIN(".word 0"))
        #define OBF_TRAP_5 BLOCK_FALSE(OBF_ASM_PLAIN("svc #0"))
    #elif OBF_MSVC && OBF_X86 && !OBF_64BIT
        // MSVC has inline asm only for x86. MSVC does not register-track __asm, so
        // every block is either an untracked no-op encoding or a balanced pair.
        #define OBF_ASM_EMIT(...) __asm { __VA_ARGS__ }

        #define OBF_BRK_0  OBF_ASM_EMIT(_emit 0x90)
        #define OBF_BRK_1  OBF_ASM_EMIT(_emit 0x3E) OBF_ASM_EMIT(_emit 0x90)
        #define OBF_BRK_2  OBF_ASM_EMIT(_emit 0x64) OBF_ASM_EMIT(_emit 0x90)
        #define OBF_BRK_3  OBF_ASM_EMIT(_emit 0x2E) OBF_ASM_EMIT(_emit 0x90)
        #define OBF_BRK_4  OBF_ASM_EMIT(_emit 0x0F) OBF_ASM_EMIT(_emit 0x1F) OBF_ASM_EMIT(_emit 0x00)
        #define OBF_BRK_5  OBF_ASM_EMIT(_emit 0x87) OBF_ASM_EMIT(_emit 0xC0)
        #define OBF_BRK_6  OBF_ASM_EMIT(pushfd) OBF_ASM_EMIT(popfd)
        #define OBF_BRK_7  OBF_ASM_EMIT(_emit 0xF5) OBF_ASM_EMIT(_emit 0xFC)
        #define OBF_BRK_8  OBF_ASM_EMIT(_emit 0x8D) OBF_ASM_EMIT(_emit 0x64) OBF_ASM_EMIT(_emit 0x24) OBF_ASM_EMIT(_emit 0x00)
        #define OBF_BRK_9  OBF_ASM_EMIT(_emit 0x65) OBF_ASM_EMIT(_emit 0x90)
        #define OBF_BRK_10 OBF_ASM_EMIT(_emit 0x36) OBF_ASM_EMIT(_emit 0x90)
        #define OBF_BRK_11 OBF_BRK_ARITH(0x11)

        #define OBF_TRAP_0 BLOCK_FALSE(OBF_ASM_EMIT(_emit 0xCC))
        #define OBF_TRAP_1 BLOCK_FALSE(OBF_ASM_EMIT(_emit 0x0F) OBF_ASM_EMIT(_emit 0xFF))
        #define OBF_TRAP_2 BLOCK_FALSE(OBF_ASM_EMIT(_emit 0xF1))
        #define OBF_TRAP_3 BLOCK_FALSE(OBF_ASM_EMIT(_emit 0xF4))
        #define OBF_TRAP_4 BLOCK_FALSE(OBF_ASM_EMIT(_emit 0xFF) OBF_ASM_EMIT(_emit 0xFF))
        #define OBF_TRAP_5 BLOCK_FALSE(OBF_ASM_EMIT(_emit 0x00) OBF_ASM_EMIT(_emit 0x00))
    #elif OBF_MSVC && OBF_X86
        // MSVC x64: no inline asm, but the intrinsics still emit real instruction bytes.
        #if _MSC_VER >= 1920
            #define OBF_BRK_0  __nop()
            #define OBF_BRK_1  _mm_pause()
            #define OBF_BRK_2  __nop()
            #define OBF_BRK_3  OBF_BRK_ARITH(3)
            #define OBF_BRK_4  __nop()
            #define OBF_BRK_5  OBF_BRK_ARITH(5)
            #define OBF_BRK_6  __nop()
            #define OBF_BRK_7  OBF_BRK_ARITH(7)
            #define OBF_BRK_8  __nop()
            #define OBF_BRK_9  OBF_BRK_ARITH(9)
            #define OBF_BRK_10 __nop()
            #define OBF_BRK_11 OBF_BRK_ARITH(11)
        #else
            #define OBF_BRK_NONE 1
        #endif
        #define OBF_TRAP_0 BLOCK_FALSE(__debugbreak())
        #define OBF_TRAP_1 BLOCK_FALSE(__debugbreak())
        #define OBF_TRAP_2 BLOCK_FALSE(__debugbreak())
        #define OBF_TRAP_3 BLOCK_FALSE(__debugbreak())
        #define OBF_TRAP_4 BLOCK_FALSE(__debugbreak())
        #define OBF_TRAP_5 BLOCK_FALSE(__debugbreak())
    #else
        #define OBF_BRK_NONE 1
    #endif

    #ifndef OBF_BRK_0
        #define OBF_BRK_NONE 1
    #endif

    #if OBF_ASM_ENABLED && !defined(OBF_BRK_NONE)
    #ifdef __cplusplus
    namespace obf { namespace brk {

        template <int Id> struct block;
        #define OBF_BRK_DECLARE(n) \
            template <> struct block<n> { static INLINE void run() { OBF_BRK_##n; } }

        OBF_BRK_DECLARE(0);  OBF_BRK_DECLARE(1);  OBF_BRK_DECLARE(2);  OBF_BRK_DECLARE(3);
        OBF_BRK_DECLARE(4);  OBF_BRK_DECLARE(5);  OBF_BRK_DECLARE(6);  OBF_BRK_DECLARE(7);
        OBF_BRK_DECLARE(8);  OBF_BRK_DECLARE(9);  OBF_BRK_DECLARE(10); OBF_BRK_DECLARE(11);

        template <int Id> struct trap;
        #define OBF_TRAP_DECLARE(n) \
            template <> struct trap<n> { static INLINE void run() { OBF_TRAP_##n; } }

        OBF_TRAP_DECLARE(0); OBF_TRAP_DECLARE(1); OBF_TRAP_DECLARE(2);
        OBF_TRAP_DECLARE(3); OBF_TRAP_DECLARE(4); OBF_TRAP_DECLARE(5);

        // The combiner. Four independent draws pick the executed blocks and their
        // order, so a single site has 12^4 shapes and no two sites disassemble alike.
        template <int A, int B, int C, int D>
        struct mix {
            static INLINE void run() {
                block<A % OBF_BRK_VARIANTS>::run();
                block<B % OBF_BRK_VARIANTS>::run();
                if ((C & 1) != 0) {
                    block<C % OBF_BRK_VARIANTS>::run();
                    block<(A + B + C) % OBF_BRK_VARIANTS>::run();
                } else {
                    block<(C + 1) % OBF_BRK_VARIANTS>::run();
                    block<(D + 3) % OBF_BRK_VARIANTS>::run();
                }
            }
        };

        // Same mix, with unreachable trap encodings welded into it.
        template <int A, int B, int C, int D>
        struct trap_mix {
            static INLINE void run() {
                mix<A, B, C, D>::run();
                #if JUNK_TRAP
                    trap<A % OBF_TRAP_VARIANTS>::run();
                    if ((D & 1) != 0) trap<B % OBF_TRAP_VARIANTS>::run();
                #endif
            }
        };
    }}
    #endif
    #endif

    #if OBF_ASM_ENABLED && !defined(OBF_BRK_NONE)
        #ifdef __cplusplus
            #define OBF_BRK_PICK4 mix<RND(0, OBF_BRK_VARIANTS - 1), RND(0, OBF_BRK_VARIANTS - 1), \
                                      RND(0, OBF_BRK_VARIANTS - 1), RND(0, OBF_BRK_VARIANTS - 1)>
            #define ASM_JUNK  obf::brk::OBF_BRK_PICK4::run()
            #define STACKBRK  obf::brk::trap_mix<RND(0, OBF_BRK_VARIANTS - 1), RND(0, OBF_BRK_VARIANTS - 1), \
                                                  RND(0, OBF_BRK_VARIANTS - 1), RND(0, OBF_BRK_VARIANTS - 1)>::run()
        #else
            #define ASM_JUNK  do { OBF_BRK_0; OBF_BRK_2; OBF_BRK_5; } while (0)
            #define STACKBRK  do { OBF_BRK_1; OBF_BRK_4; OBF_TRAP_0; } while (0)
        #endif
    #else
        #define ASM_JUNK   ((void)0)
        #define STACKBRK   ((void)0)
    #endif

/* =============================================================================
 * 7. CONTROL FLOW
 *
 * Two gates with the same contract - both return their argument unchanged - and
 * different strengths:
 *
 *   obf_kd_map  NOINLINE, reads the volatile pool and may embed asm. Cannot be
 *                 evaluated at compile time, so CFLOW_ASM_JUNK=0 swaps cflow over
 *                 to the gate below instead of forcing the user to give up cflow.
 *   obf_kc_map   NOINLINE *and* constexpr. No volatile, no asm, therefore legal
 *                 inside constexpr/static_assert, while noinline keeps the call
 *                 from being erased in ordinary code.
 *
 * Every branch in both gates is value preserving, so a mispredicted or dead path
 * can never return a wrong value.
 * ============================================================================= */

    #if OBF_IBRANCH_ENABLED && OBF_GNU && (OBF_X86 || OBF_ARM) && OBF_ASM_ENABLED
        // Zeroes a scratch register the compiler owns, then branches over a byte that
        // disassemblers read as the start of an instruction.
        #if OBF_X86
            #define OBF_INDIRECT_BRANCH                                                                              \
                do { OBF_UINT obf_ib_ = 1;                                                                           \
                     __asm__ __volatile__("xor %0, %0" "\n\t" "jz 1f" "\n\t" ".byte 0x00" "\n\t" "1:" : "+r"(obf_ib_)); \
                     (void)obf_ib_; } while (0)
        #elif OBF_64BIT
            #define OBF_INDIRECT_BRANCH                                                                              \
                do { OBF_UINT obf_ib_ = 1;                                                                           \
                     __asm__ __volatile__("cmp %0, %0" "\n\t" "b.eq 1f" "\n\t" ".word 0xd4200000" "\n\t" "1:" : "+r"(obf_ib_)); \
                     (void)obf_ib_; } while (0)
        #else
            #define OBF_INDIRECT_BRANCH                                                                              \
                do { unsigned obf_ib_ = 1;                                                                           \
                     __asm__ __volatile__("teq %0, %0" "\n\t" "beq 1f" "\n\t" ".word 0xe7f001f0" "\n\t" "1:" : "+l"(obf_ib_)); \
                     (void)obf_ib_; } while (0)
        #endif
    #elif OBF_IBRANCH_ENABLED && OBF_MSVC && OBF_X86 && !OBF_64BIT
        // eax and the flags are saved by hand: MSVC inline asm is not register tracked.
        // One __asm block per instruction: the macro's line continuations collapse this
        // into a single physical line, and MSVC's inline assembler rejects a braced block
        // holding several instructions written that way (C2400/C4405).
        #define OBF_INDIRECT_BRANCH           \
            __asm { push eax }                \
            __asm { pushfd }                  \
            __asm { xor eax, eax }            \
            __asm { _emit 0x74 }              \
            __asm { _emit 0x01 }              \
            __asm { _emit 0xCC }              \
            __asm { popfd }                   \
            __asm { pop eax }
    #else
        #define OBF_INDIRECT_BRANCH ((void)0)
    #endif

    // Public spelling, kept for compatibility with existing code.
    #ifndef INDIRECT_BRANCH
        #define INDIRECT_BRANCH OBF_INDIRECT_BRANCH
    #endif

    #ifdef __cplusplus
        #define OBF_CX constexpr
    #else
        #define OBF_CX
    #endif

    // The runtime gate. It only exists when asm junk is allowed, because with
    // CFLOW_ASM_JUNK=0 every cflow construct has to stay constexpr compatible.
    #if CFLOW_ASM_JUNK
    static NOINLINE OBF_CF_T obf_kd_map(OBF_CF_T v) {
        OBF_INDIRECT_BRANCH;
        volatile OBF_CF_T kept = v;
        // (a != b) + (a == b) is exactly one whatever the two cells hold, so the
        // multiply preserves v without writing down a constant and without assuming
        // the pool contains any particular byte (the old version needed 7 - 3*2 == 1).
        const unsigned p = obf_vb_4, q = obf_vb_8;
        const OBF_CF_T one = (OBF_CF_T)(p != q) + (OBF_CF_T)(p == q);
        OBF_CF_T a = kept * one;
        // Every decoy branch xors with the same cell twice: an involution that cannot
        // corrupt a even if it were reached, and the operand comes back from a volatile
        // load so the optimizer cannot pair the two xors up and cancel them.
        BLOCK_FALSE(a = XOR(XOR(a, (OBF_CF_T)obf_vb_5), (OBF_CF_T)obf_vb_5));
        BLOCK_TRUE (a = XOR(XOR(a, (OBF_CF_T)obf_vb_9), (OBF_CF_T)obf_vb_9));
        BLOCK_FALSE(a = (OBF_CF_T)(a + (OBF_CF_T)obf_vb_0 * one));
        ASM_JUNK;
        obf_cf_end:
        if (obf_vb_1 != 0u) {
            return a;
        }
        obf_cf_fake:
        return a;
    }
    #endif

    // The compile-time gate.
    static NOINLINE OBF_CX OBF_CF_T obf_kc_map(OBF_CF_T v) {
        const OBF_CF_T k = (OBF_CF_T)OBF_BUILD_SALT * 2654435761ull + 1ull;
        OBF_CF_T a = v;
        a = XOR(a, k);
        a = XOR(a, k);
        if ((a | 1ull) - (a & ~(OBF_CF_T)1ull) == 1ull) {
            a = XOR(XOR(a, (OBF_CF_T)1ull), (OBF_CF_T)1ull);
        } else {
            a = XOR(XOR(a, k), k);
        }
        return (OBF_CF_T)(a + (a & 0ull));
    }

    #if CFLOW_ASM_JUNK
        #define OBF_CF_MAP(v) obf_kd_map((OBF_CF_T)(v))
    #else
        #define OBF_CF_MAP(v) obf_kc_map((OBF_CF_T)(v))
    #endif

    // Junk that runs around a mutated `return`: it is an expression, so it can be
    // welded into a statement without changing which statement it belongs to, and it
    // stays constexpr legal when the asm junk is turned off.
    #if CFLOW_ASM_JUNK
        #define OBF_CF_STEP(v) obf_kd_map((OBF_CF_T)(v))
    #else
        #define OBF_CF_STEP(v) obf_kc_map((OBF_CF_T)(v))
    #endif

    // A hard fault on purpose, for paths that must never be reached.
    #define SEGFAULT (void)OBF_CF_MAP((OBF_CF_T) * (volatile int*)(uintptr_t)RND(1, 0x7FFFFF))

    #ifdef __cplusplus
    namespace obf {

        // Truthiness without the cast: bool(v) is valid for integrals, enums, pointers
        // and class types with an explicit operator bool, and it keeps 0.5f truthy
        // where casting to an integer would have silently turned the branch false.
        template <class T>
        INLINE constexpr OBF_UINT as_flag(T v) { return (OBF_UINT)(bool)v; }

        // Conditions may contain commas, so the hijacked keywords take a pack and keep
        // only the last value: if (a, b) behaves exactly like plain C.
        template <class... Args>
        INLINE constexpr OBF_UINT cond_last(Args... args) {
            OBF_UINT vals[] = { 0u, (as_flag(args))... };
            return vals[sizeof...(Args)];
        }

        // switch() needs the value itself, not its truthiness.
        template <class... Args>
        INLINE constexpr long long val_last(Args... args) {
            long long vals[] = { 0, (long long)(args)... };
            return vals[sizeof...(Args)];
        }
    }
    #define OBF_CF_COND(...) obf::cond_last(__VA_ARGS__)
    #define OBF_CF_VALUE(...) obf::val_last(__VA_ARGS__)
    #else
    #define OBF_CF_COND(x) ((OBF_UINT)(x))
    #define OBF_CF_VALUE(x) ((long long)(x))
    #endif

    // nonzero in, nonzero out, plus a per-site constant conjure. Variadic so that
    // conditions containing commas keep working.
    #define OBF_CF_TRUTH(...) (OBF_CF_MAP(OBF_CF_COND(__VA_ARGS__)) != (OBF_UINT)0 && OBF_RAND != 0)
    #define OBF_CF_SWITCH(...) ((long long)OBF_CF_MAP((OBF_UINT)OBF_CF_VALUE(__VA_ARGS__)))

/* =============================================================================
 * 8. METAPROGRAMMING
 *
 * A frozen copy of the handful of <type_traits> pieces this header needs, so a
 * standard library upgrade can never change how OBF() decays a type. Written
 * against C++14 and never updated on purpose.
 * ============================================================================= */

#ifdef __cplusplus
namespace meta {

    template <class T, T v>
    struct integral_constant {
        static constexpr T value = v;
        typedef T value_type;
        typedef integral_constant type;
        constexpr operator value_type() const noexcept { return value; }
        constexpr value_type operator()() const noexcept { return value; }
    };

    typedef integral_constant<bool, false> false_type;
    typedef integral_constant<bool, true> true_type;

    // Function types have to be recognized before decay turns them into pointers,
    // otherwise encrypting anything callable would silently change its type.
    template <class> struct is_function : false_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...)> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...)> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...) const> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...) volatile> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...) const volatile> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...) const> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...) volatile> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...) const volatile> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...)&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...) const&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...) volatile&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...) const volatile&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...)&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...) const&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...) volatile&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...) const volatile&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...)&&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...) const&&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...) volatile&&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args...) const volatile&&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...)&&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...) const&&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...) volatile&&> : true_type {};
    template <class Ret, class... Args> struct is_function<Ret(Args..., ...) const volatile&&> : true_type {};

    template <class T> struct is_array : false_type {};
    template <class T> struct is_array<T[]> : true_type {};
    template <class T, size_t N> struct is_array<T[N]> : true_type {};

    // OBF() cannot reach the bit pattern of a float at compile time before C++20,
    // so the type is named explicitly instead of failing inside the cipher.
    template <class T> struct is_floating_point : false_type {};
    template <> struct is_floating_point<float> : true_type {};
    template <> struct is_floating_point<double> : true_type {};
    template <> struct is_floating_point<long double> : true_type {};

    template <class T> struct remove_extent { typedef T type; };
    template <class T> struct remove_extent<T[]> { typedef T type; };
    template <class T, size_t N> struct remove_extent<T[N]> { typedef T type; };

    template <class T> struct remove_reference { typedef T type; };
    template <class T> struct remove_reference<T&> { typedef T type; };
    template <class T> struct remove_reference<T&&> { typedef T type; };

    template <class T> struct remove_cv { typedef T type; };
    template <class T> struct remove_cv<const T> { typedef T type; };
    template <class T> struct remove_cv<volatile T> { typedef T type; };
    template <class T> struct remove_cv<const volatile T> { typedef T type; };

    template <class T> struct remove_const { typedef T type; };
    template <class T> struct remove_const<const T> { typedef T type; };

    template <class T> struct remove_volatile { typedef T type; };
    template <class T> struct remove_volatile<volatile T> { typedef T type; };

    template <class T> struct remove_all_extents { typedef T type; };
    template <class T> struct remove_all_extents<T[]> { typedef typename remove_all_extents<T>::type type; };
    template <class T, size_t N> struct remove_all_extents<T[N]> { typedef typename remove_all_extents<T>::type type; };

    template <bool B, class T, class F> struct conditional { typedef T type; };
    template <class T, class F> struct conditional<false, T, F> { typedef F type; };

    template <class T> struct type_identity { typedef T type; };
    // SFINAE on whether T* can be formed at all, which is how functions decay to
    // pointers while arrays decay to their element pointer.
    template <class T> auto try_add_pointer(int)->type_identity<typename remove_reference<T>::type*>;
    template <class T> auto try_add_pointer(...)->type_identity<T>;
    template <class T> struct add_pointer : decltype(try_add_pointer<T>(0)) {};

    template <class T> using remove_cv_t = typename remove_cv<T>::type;
    template <class T> using remove_const_t = typename remove_const<T>::type;
    template <class T> using remove_volatile_t = typename remove_volatile<T>::type;
    template <class T> using remove_reference_t = typename remove_reference<T>::type;
    template <class T> using remove_all_extents_t = typename remove_all_extents<T>::type;

    template <class T>
    struct decay {
    private:
        typedef typename remove_reference<T>::type U;
    public:
        typedef typename conditional<
            is_array<U>::value,
            typename add_pointer<typename remove_extent<U>::type>::type,
            typename conditional<
                is_function<U>::value,
                typename add_pointer<U>::type,
                typename remove_cv<U>::type
            >::type
        >::type type;
    };

    template <class T> using decay_t = typename decay<T>::type;
}
#endif

/* =============================================================================
 * 9. COMPILE-TIME CONSTANT ENCRYPTION
 *
 * Everything is computed by the compiler: only cipher bytes reach the object file,
 * the plaintext never does. Three designs are worth calling out:
 *
 *   - The payload is stored in an unsigned integer of the same width as the source
 *     type, not in the source type itself. That is what makes OBF(true) work: with
 *     bool storage the key was truncated to one bit at encrypt time while the
 *     decryptor tested for non-zero, so the value came back wrong. The old header
 *     hid that behind "#define true 1", which is gone now.
 *   - Each payload lives in a table of VAULT_SLOTS same-sized rows where only one
 *     row is real, reached through a masked index recovered by a non-inlinable
 *     call. That hides the reference the same way the call tables do in section 11.
 *   - The key schedule is a hash of (key, index) instead of (key + index), and the
 *     xor is chosen per instantiation out of five algebraic identities, so two
 *     identical literals never decrypt through the same code.
 * ============================================================================= */

#ifdef __cplusplus
namespace obf {

    template <class T>
    using clean_type = typename meta::remove_const_t<meta::remove_reference_t<T>>;

    // Overload tricks used only inside decltype(): declaring (never defining) the
    // array overload tells apart a buffer from a scalar and reports its element type,
    // and the matching getsize reports the length. Nothing is emitted for gettype.
    template <typename T, size_t size> constexpr size_t getsize(const T(&)[size]) { return size; }
    template <typename T> constexpr size_t getsize(T) { return 1; }
    template <typename T, size_t size> T gettype(const T(&)[size]);
    template <typename T> T gettype(T);

    template <class X>
    struct payload {
        typedef clean_type<X> type;
        typedef typename cipher_of<type>::type cipher_type;
    };
    template <class X> using payload_t = typename payload<X>::type;
    template <class X> using cipher_t  = typename payload<X>::cipher_type;

    // Runtime decryption of one row. The fake branches xor with a decoy key twice:
    // they can never corrupt the result even if they were reached, and because the
    // key comes back from a non-inlinable call the optimizer cannot pair them up
    // and cancel them either.
    template <class U, unsigned char Key, size_t Size, int Variant>
    INLINE void xor_decode(U* row) {
#if CFLOW_CONST_DECRYPTION
        for (volatile size_t i = 0; i < Size; ++i) {
            const OBF_CF_T base = (OBF_CF_T)key_at<U>(Key, (unsigned)i);
            BLOCK_FALSE(row[i] = cipher<U, Variant>::mix(cipher<U, Variant>::mix(row[i], (U)OBF_CF_MAP(base + 1u)), (U)OBF_CF_MAP(base + 1u)))
            BLOCK_TRUE(
                BLOCK_FALSE(row[i] = cipher<U, Variant>::mix(cipher<U, Variant>::mix(row[i], (U)OBF_CF_MAP(base + 2u)), (U)OBF_CF_MAP(base + 2u)))
                BLOCK_FALSE(row[i] = cipher<U, Variant>::mix(cipher<U, Variant>::mix(row[i], (U)OBF_CF_MAP(base + 3u)), (U)OBF_CF_MAP(base + 3u)))
                BLOCK_TRUE(row[i] = cipher<U, Variant>::mix(row[i], (U)OBF_CF_MAP(base))) // real
            )
            BLOCK_FALSE(row[i] = cipher<U, Variant>::mix(cipher<U, Variant>::mix(row[i], (U)OBF_CF_MAP(base + 4u)), (U)OBF_CF_MAP(base + 4u)))
        }
#else
        for (size_t i = 0; i < Size; ++i)
            row[i] = cipher<U, Variant>::mix(row[i], key_at<U>(Key, (unsigned)i));
#endif
    }

    template <class T, class U, size_t Size, unsigned char Key, int Slots, int Real, unsigned Seed, int Variant>
    class vault {
        static_assert(Size > 0, "obfusheader: empty payload");
        static_assert(Slots > 0 && Real >= 0 && Real < Slots, "obfusheader: vault slot out of range");
        static_assert(!meta::is_floating_point<T>::value,
                      "obfusheader: OBF() cannot encrypt a floating point literal, its bit pattern is not reachable at compile time before C++20");

    public:
        INLINE constexpr vault(const T* src) { fill(src); }
        // The scalar path is spelled out separately: Visual C++ refuses to
        // constant-evaluate a constructor that reaches the value through the address
        // of its own parameter, so `fill(&value)` would silently fail here.
        INLINE constexpr vault(T value) { fill_value(value); }

        INLINE operator T*() { return reinterpret_cast<T*>(decoded()); }
        INLINE operator T() { return (T)decoded()[0]; }

    private:
        // The row index is stored masked, so no instruction carries the real slot.
        INLINE static constexpr unsigned mask() { return (Seed * k::mul32(OBF_K_SLOT)) & 0xFFFFu; }
        INLINE static int slot() {
            return (int)(OBF_CF_MAP((OBF_CF_T)((OBF_CF_T)Real ^ (OBF_CF_T)mask())) ^ (OBF_CF_T)mask());
        }

        // Junk rows come from the site seed: same width, same look, no meaning.
        INLINE static constexpr unsigned decoy_byte(int row, unsigned index) {
            unsigned long long h = ((unsigned long long)Seed + (unsigned long long)(row + 1) * k::mul64(OBF_K_KA))
                                 ^ ((unsigned long long)index * k::mul64(OBF_K_D1));
            h ^= h >> k::shr(OBF_K_D2, 28u, 40u); h *= k::mul64(OBF_K_KC); h ^= h >> k::shr(OBF_K_S2, 25u, 36u);
            return (unsigned)h;
        }

        // The payload checksum, taken over the plaintext at compile time and over the
        // decrypted row at run time. Its seed and multiplier are the build's own: the
        // run-time half is real code and the published FNV numbers would show up in it.
        INLINE static constexpr unsigned hash_step(unsigned h, U v) {
            const unsigned mul = k::mul32(OBF_K_MUL);
            for (size_t b = 0; b < sizeof(U); ++b)
                h = XOR(h, (unsigned)((v >> (b * 8u)) & 0xFFu)) * mul;
            return h;
        }

        INLINE static constexpr unsigned check_seed() { return k::mul32(OBF_K_SEED); }

        INLINE constexpr void fill(const T* src) {
            unsigned h = check_seed();
            for (int s = 0; s < Slots; ++s) {
                const bool real = (s == Real);
                for (size_t i = 0; i < Size; ++i) {
                    if (real) {
                        const U plain = (U)src[i];
                        h = hash_step(h, plain);
                        rows_[s][i] = cipher<U, Variant>::mix(plain, key_at<U>(Key, (unsigned)i));
                    } else {
                        rows_[s][i] = (U)decoy_byte(s, (unsigned)i);
                    }
                }
            }
            check_ = XOR(h, mask());
        }

        // Same job for a scalar literal, spelled out instead of calling fill(&value):
        // Visual C++ refuses to constant-evaluate a constructor that reaches the value
        // through the address of its own parameter (C3615), while clang folds it happily.
        INLINE constexpr void fill_value(T value) {
            unsigned h = check_seed();
            for (int s = 0; s < Slots; ++s) {
                const bool real = (s == Real);
                for (size_t i = 0; i < Size; ++i) {
                    if (real) {
                        const U plain = (U)value;
                        h = hash_step(h, plain);
                        rows_[s][i] = cipher<U, Variant>::mix(plain, key_at<U>(Key, (unsigned)i));
                    } else {
                        rows_[s][i] = (U)decoy_byte(s, (unsigned)i);
                    }
                }
            }
            check_ = XOR(h, mask());
        }

        INLINE U* decoded() {
            U* row = &rows_[slot()][0];
            if (ready_ == 0u) {
                ready_ = 1u;
                xor_decode<U, Key, Size, Variant>(row);
#if VAULT_CHECK
                // Recompute a checksum the compiler took from the plaintext. If the
                // ciphertext or the decryptor was patched it no longer matches, so the
                // payload is quietly re-encrypted instead of handed out.
                unsigned h = check_seed();
                for (size_t i = 0; i < Size; ++i) h = hash_step(h, row[i]);
                if (h != (unsigned)XOR(check_, mask())) {
                    xor_decode<U, Key, Size, Variant>(row);
                    STACKBRK;
                }
#endif
            }
            return row;
        }

        // Every member gets a default initializer: Visual C++'s constexpr evaluator
        // requires all of them to be constructed before the constructor body runs, and
        // rejects the constructor otherwise (C3615) even though the body assigns every
        // element. clang accepts either form, so this has to be tested on MSVC.
        U rows_[Slots][Size]{};
        unsigned check_ = 0u;
        unsigned char ready_ = 0u;
    };
}

    // A payload has to be produced by a *constexpr static* initializer: constant
    // initialization is what lets the compiler drop the plaintext literal, so a
    // temporary built by a plain expression would leave the original bytes in .rdata.
    // That is why MAKEOBF keeps the immediately invoked lambda, and why the return
    // hijack in section 15 is written so that every path still returns.
    //
    // THREADLOCAL mode decrypts once per thread and hands out a copy of that.
    #define OBF_KEY_NORMAL(x, args) []() { \
        constexpr static auto obf_stored = obf::vault<args>(x); \
        return obf_stored; }()
    #define OBF_KEY_THREADLOCAL(x, args) []() { \
        constexpr static auto obf_stored = obf::vault<args>(x); \
        thread_local auto obf_cached = obf_stored; \
        return obf_cached; }()

    #define OBF_VAULT_ARGS(x) \
        obf::payload_t<decltype(obf::gettype(x))>, obf::cipher_t<decltype(obf::gettype(x))>, \
        obf::getsize(x), (unsigned char)RND(1, 255), VAULT_SLOTS, RND(0, VAULT_SLOTS - 1), \
        (unsigned)RND(1, 0xFFFF), RND(0, OBF_CIPHER_VARIANTS - 1)

#if CONST_ENCRYPTION
    #if CONST_ENCRYPT_MODE == OBF_MODE_NORMAL
        #define MAKEOBF(x) OBF_KEY_NORMAL(x, OBF_VAULT_ARGS(x))
    #else
        #define MAKEOBF(x) OBF_KEY_THREADLOCAL(x, OBF_VAULT_ARGS(x))
    #endif
    #define OBF(x) ((meta::decay_t<decltype(x)>)MAKEOBF(x))
#else
    #define MAKEOBF(x) x
    #define OBF(x) x
#endif

/* Legacy C path: no constexpr, so nothing can be encrypted at compile time. */
#else
    #define MAKEOBF(x) x
    #define OBF(x) x
#endif

/* =============================================================================
 * 10. WATERMARKING
 *
 * Messages are pushed through a volatile function pointer that is initialized to a
 * real function, so the strings survive every optimization and still show up in a
 * decompiler's cross-reference window as a plausible drawing routine.
 *
 * The internal names carry no project name any more: a MinGW build that ships
 * unstripped leaves every static symbol in the image, and "obfusheader_" in the
 * symbol table is a one-instruction signature. Strip the release binary anyway.
 * ============================================================================= */

#if WATERMARKING
    static void obf_present_draw(const char* param) { ASM_JUNK; OBF_UNUSED(param); }
    typedef void (*draw_ptr)(const char*);
    static volatile draw_ptr obf_prev_draw = (draw_ptr)obf_present_draw;

    #define WATERMARK(...)                                                       \
        const char* obf_wm_[] = { __VA_ARGS__ };                                 \
        for (volatile size_t obf_wm_i_ = 0;                                      \
             obf_wm_i_ < sizeof(obf_wm_) / sizeof(obf_wm_[0]); ++obf_wm_i_)      \
            obf_prev_draw(obf_wm_[obf_wm_i_]);
#endif

// Referenced by the call hiding decoys, so it exists either way: its only job is to
// keep the drawing routine referenced by something the linker is not allowed to
// drop, which is what makes it show up in a decompiler at all.
//
// It used to pass the header's own three sentences down that path. Those were plain
// text in .rdata in every binary built from this file, which made them the single
// cheapest way to find obfusheader: match the string, match the header. A watermark is
// only meaningful when the author supplies the text (WATERMARK("...")), so the decoy
// now feeds the routine a buffer drawn from the per-build entropy instead: the
// mechanism, the xref and the surviving bytes all stay, the fixed phrase goes away.
static void obf_wm_sink() {
#if WATERMARKING
    static volatile char obf_wm_pad[24] = {
        (char)RND(32, 122), (char)RND(32, 122), (char)RND(32, 122), (char)RND(32, 122),
        (char)RND(32, 122), (char)RND(32, 122), (char)RND(32, 122), (char)RND(32, 122),
        (char)RND(32, 122), (char)RND(32, 122), (char)RND(32, 122), (char)0,
        (char)RND(32, 122), (char)RND(32, 122), (char)RND(32, 122), (char)RND(32, 122),
        (char)RND(32, 122), (char)RND(32, 122), (char)RND(32, 122), (char)RND(32, 122),
        (char)RND(32, 122), (char)RND(32, 122), (char)RND(32, 122), (char)0
    };
    obf_prev_draw((const char*)obf_wm_pad);
    obf_prev_draw((const char*)obf_wm_pad + 12);
#endif
    ASM_JUNK;
}

/* =============================================================================
 * 11. CALL HIDING
 *
 * The address is read out of a table whose slot order is decided at compile time,
 * and the index itself is recovered through a non-inlinable call, so neither the
 * call site nor the table points at the target in an obvious way. The other slots
 * hold the decoy stubs above and impossible addresses; they are never selected.
 * ============================================================================= */

#ifdef __cplusplus
    static void obf_stub_1() { obf_wm_sink(); ASM_JUNK; }
    static void obf_stub_2() { obf_stub_1(); ASM_JUNK; }
    static void obf_stub_3() { ASM_JUNK; obf_stub_2(); }
    static void obf_stub_4() { STACKBRK; }
    static void obf_stub_5() { ASM_JUNK; obf_stub_2(); }
    static void obf_stub_6() { ASM_JUNK; obf_stub_3(); }
    static void obf_stub_7() { obf_stub_5(); ASM_JUNK; }
    static void obf_stub_8() { STACKBRK; ASM_JUNK; }

    namespace obf {

        #define OBF_DECOY_COUNT 8

        template <typename T, unsigned Seed, int Slot>
        INLINE T call_decoy() {
            const unsigned pick = (unsigned)((Seed + (unsigned)Slot * k::byte(OBF_K_DECOY)) % OBF_DECOY_COUNT);
            switch ((int)pick) {
                case 0:  return RCAST(T, &obf_stub_1);
                case 1:  return RCAST(T, &obf_stub_2);
                case 2:  return RCAST(T, &obf_stub_3);
                case 3:  return RCAST(T, &obf_stub_4);
                case 4:  return RCAST(T, &obf_stub_5);
                case 5:  return RCAST(T, &obf_stub_6);
                case 6:  return RCAST(T, &obf_stub_7);
                default: return RCAST(T, &obf_stub_8);
            }
        }

        template <typename T, int Real, T Value, unsigned Seed, int Slot>
        INLINE T call_entry() {
            ASM_JUNK;
            if (Slot == Real)
                return Value;
            if ((Slot % 3) == 0)
                return RCAST(T, (OBF_UINT)OBF_RAND); // never selected: bait for the disassembler
            return call_decoy<T, Seed, Slot>();
        }

        template <typename T, int N, int Real, T Value, unsigned Seed, int... Slots>
        struct call_hider {
            static_assert(sizeof...(Slots) == (size_t)N, "obfusheader: the slot list must match CALL_SLOTS");
            static_assert(Real >= 0 && Real < N, "obfusheader: call slot index out of range");

            static T table[N];

            // The index is derived from the template argument, never from a second
            // RND() draw: expanding the draw twice is what used to make the table
            // return a decoy instead of the target.
            static INLINE T get() {
                const OBF_CF_T m = (OBF_CF_T)(Seed * k::mul32(OBF_K_SLOT)) & 0xFFFFu;
                return table[(int)(OBF_CF_MAP((OBF_CF_T)Real ^ m) ^ m)];
            }
        };

        template <typename T, int N, int Real, T Value, unsigned Seed, int... Slots>
        T call_hider<T, N, Real, Value, Seed, Slots...>::table[N] = { call_entry<T, Real, Value, Seed, Slots>()... };
    }

    // The index pack handed to call_hider must contain exactly CALL_SLOTS entries, so
    // the list is picked by pasting the configured number onto its own spelling.
    #define OBF_CALL_SLOT_LIST_2  0, 1
    #define OBF_CALL_SLOT_LIST_3  0, 1, 2
    #define OBF_CALL_SLOT_LIST_4  0, 1, 2, 3
    #define OBF_CALL_SLOT_LIST_5  0, 1, 2, 3, 4
    #define OBF_CALL_SLOT_LIST_6  0, 1, 2, 3, 4, 5
    #define OBF_CALL_SLOT_LIST_7  0, 1, 2, 3, 4, 5, 6
    #define OBF_CALL_SLOT_LIST_8  0, 1, 2, 3, 4, 5, 6, 7
    #define OBF_CALL_SLOT_LIST_9  0, 1, 2, 3, 4, 5, 6, 7, 8
    #define OBF_CALL_SLOT_LIST_10 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
    #define OBF_CALL_SLOT_PICK(n)  OBF_CALL_SLOT_LIST_##n
    #define OBF_CALL_SLOT_LIST(n)  OBF_CALL_SLOT_PICK(n)
    #define OBF_CALL_SLOTS_LIST    OBF_CALL_SLOT_LIST(CALL_SLOTS)

    #define HIDE_PTR_I(ptr, index) \
        obf::call_hider<meta::decay_t<decltype(ptr)>, CALL_SLOTS, (index), (ptr), \
                        (unsigned)RND(1, 0xFFFF), OBF_CALL_SLOTS_LIST>::get()
    #define HIDE_PTR(ptr) HIDE_PTR_I(ptr, RND(0, CALL_SLOTS - 1))
    #define CALL(ptr, ...) (HIDE_PTR(ptr)(__VA_ARGS__))
#else
    #define HIDE_PTR(ptr) (ptr)
    #define HIDE_PTR_I(ptr, index) (ptr)
    #define CALL(ptr, ...) ((ptr)(__VA_ARGS__))
#endif

/* =============================================================================
 * 12. IMPORT HIDING
 *
 * The API is found by parsing the loader's own data instead of asking for it:
 *   Windows - TEB -> PEB -> Ldr->InMemoryOrderModuleList, then the PE export
 *             directory of the matching module.
 *   Linux   - the image's DT_DEBUG -> the linker's r_debug -> the link map chain,
 *             then each object's GNU or SYSV symbol hash table.
 * Names are matched by compile-time hashes mixed with a per-build salt, so neither
 * "LoadLibraryA" nor "kernel32.dll" is ever stored in the binary. On Windows the
 * wide module name and on Linux the ELF name are re-hashed at run time and compared,
 * so a collision can never hand out the wrong function either. The result is cached
 * XOR-masked, so the slot does not look like a pointer either.
 *
 * IMPORT_RESOLVER picks the backend:
 *   OBF_RESOLVER_AUTO   manual first, GetProcAddress/dlsym if it cannot resolve
 *   OBF_RESOLVER_MANUAL manual only: no loader API is referenced at all
 *   OBF_RESOLVER_API    legacy behaviour, always through the loader API
 *
 * On Linux the link map layout is glibc's (bionic follows it); musl has a different
 * one, which the sanity checks reject, so musl resolves through the API fallback.
 * ============================================================================= */

#if OBF_WINDOWS && !KERNEL_MODE && IMPORT_RESOLVER != OBF_RESOLVER_MANUAL
    #include <windows.h>
#elif OBF_LINUX && !KERNEL_MODE && IMPORT_RESOLVER != OBF_RESOLVER_MANUAL
    #include <dlfcn.h>
#endif

#ifdef __cplusplus
namespace obf {

    // Run-time half of the name matching: these call the constexpr originals instead
    // of repeating the loop, so a compile-time OBF_HASH() is guaranteed to agree with
    // what the loader's tables are measured against, and the mixing constants are
    // emitted once rather than in four copies that could drift apart.
    INLINE unsigned hash_runtime(const char* s) {
        return hash_salt(hash_fnv(s));
    }

    INLINE unsigned hash_runtime_lower(const char* s) {
        return hash_salt(hash_fnv_lower(s));
    }

#if OBF_WINDOWS
    namespace pe {
        // Hand rolled layouts: the fields mirror the OS structures, but nothing here
        // needs <windows.h>, so the walk also works in a kernel mode build.
        struct list_entry { void* flink; void* blink; };
        struct unicode_string { unsigned short length; unsigned short maximum; void* buffer; };
        struct ldr_entry {
            list_entry load_order;
            list_entry memory_order;
            list_entry init_order;
            void* dll_base;
            void* entry_point;
            unsigned long image_size;
            unicode_string full_name;
            unicode_string base_name;
        };

        INLINE unsigned hash_wide(const void* buf, unsigned short bytes) {
            unsigned h = k::mul32(OBF_K_SEED);
            if (buf != 0) {
                const unsigned short* w = (const unsigned short*)buf;
                for (unsigned i = 0; (i + 1u) < (unsigned)bytes; i += 2u) {
                    unsigned c = (unsigned)w[i / 2u];
                    if (c >= 'A' && c <= 'Z') c = c + 32u;
                    h = hash_feed(h, c);
                }
            }
            return hash_salt(h);
        }

        INLINE void* current_peb() {
#if OBF_MSVC && OBF_X86 && OBF_64BIT
            return (void*)__readgsqword(0x60);
#elif OBF_MSVC && OBF_X86
            return (void*)__readfsdword(0x30);
#elif OBF_GNU && OBF_X86 && OBF_64BIT
            void* peb_; __asm__ __volatile__("mov %%gs:0x60, %0" : "=r"(peb_)); return peb_;
#elif OBF_GNU && OBF_X86
            void* peb_; __asm__ __volatile__("mov %%fs:0x30, %0" : "=r"(peb_)); return peb_;
#else
            return 0;
#endif
        }

        // DataDirectory[0] is the export table; its offset inside the optional header
        // depends on the PE32 / PE32+ magic, so both are read from the image itself.
        INLINE void* find_export(void* base, unsigned sym_hash) {
            unsigned char* img = (unsigned char*)base;
            if (img == 0 || img[0] != 'M' || img[1] != 'Z') return 0;
            unsigned char* nt = img + *(int*)(img + 0x3C);
            if (nt[0] != 'P' || nt[1] != 'E') return 0;
            const unsigned char* opt = nt + 24;
            const unsigned char* dirs = opt + (*(unsigned short*)opt == 0x20bu ? 112u : 96u);
            const unsigned export_rva = *(const unsigned*)dirs;
            if (export_rva == 0) return 0;
            const unsigned char* exp = img + export_rva;
            const unsigned n_names = *(const unsigned*)(exp + 24);
            const unsigned* funcs = (const unsigned*)(img + *(const unsigned*)(exp + 28));
            const unsigned* names = (const unsigned*)(img + *(const unsigned*)(exp + 32));
            const unsigned short* ords = (const unsigned short*)(img + *(const unsigned*)(exp + 36));
            if (funcs == 0 || names == 0 || ords == 0) return 0;
            for (unsigned i = 0; i < n_names; ++i) {
                if (hash_runtime((const char*)(img + names[i])) == sym_hash) {
                    const unsigned rva = funcs[ords[i]];
                    if (rva >= export_rva) return 0; // a forwarded export, let the caller fall back
                    return (void*)(img + rva);
                }
            }
            return 0;
        }

        INLINE void* resolve(unsigned mod_hash, unsigned sym_hash) {
            unsigned char* peb_ = (unsigned char*)current_peb();
            if (peb_ == 0) return 0;
            unsigned char* ldr = *(unsigned char**)(peb_ + (OBF_64BIT ? 0x18u : 0x0Cu));
            if (ldr == 0) return 0;
            list_entry* head = (list_entry*)(ldr + (OBF_64BIT ? 0x20u : 0x14u));
            list_entry* it = (list_entry*)head->flink;
            const size_t back = (size_t)((const char*)&((const ldr_entry*)0)->memory_order);
            for (int guard = 0; it != 0 && it != head && guard < 512; it = (list_entry*)it->flink, ++guard) {
                ldr_entry* e = (ldr_entry*)((unsigned char*)it - back);
                if (e->dll_base == 0) continue;
                if (mod_hash != 0 && hash_wide(e->base_name.buffer, e->base_name.length) != mod_hash)
                    continue;
                void* found = find_export(e->dll_base, sym_hash);
                if (found != 0) return found;
                if (mod_hash != 0) break; // the right module did not have it: stop looking
            }
            return 0;
        }
    }
#endif

#if OBF_LINUX
    namespace elf {
        struct dyn { long tag; unsigned long val; };
        struct sym32 { unsigned name; unsigned value; unsigned size; unsigned char info; unsigned char other; unsigned short shndx; };
        struct sym64 { unsigned name; unsigned char info; unsigned char other; unsigned short shndx; unsigned long value; unsigned long size; };
        struct r_debug { int version; void* map; void* brk; int state; void* ldbase; };
        // glibc's link_map prefix, which bionic copies. Anything else fails sane().
        struct link_map { unsigned long load_addr; char* name; dyn* dynamic; link_map* next; link_map* prev; };

        #define OBF_DT_NULL     0L
        #define OBF_DT_HASH     4L
        #define OBF_DT_STRTAB   5L
        #define OBF_DT_SYMTAB   6L
        #define OBF_DT_STRSZ   10L
        #define OBF_DT_SYMENT  11L
        #define OBF_DT_DEBUG   21L
        #define OBF_DT_GNU_HASH 0x6ffffef5L
        #define OBF_STT_IFUNC  10u
        #define OBF_SHN_UNDEF   0u

        typedef typename meta::conditional<OBF_64BIT, sym64, sym32>::type sym;

        // _DYNAMIC is a linker provided symbol. As a weak reference it reads as null in
        // a build that has no dynamic section, instead of failing to link.
        extern "C" { extern dyn _DYNAMIC[] __attribute__((weak)); }

        INLINE const dyn* tag(const dyn* d, long want) {
            for (int i = 0; d != 0 && i < 256; ++i) {
                if (d[i].tag == want) return &d[i];
                if (d[i].tag == OBF_DT_NULL) break;
            }
            return 0;
        }

        // Rejects anything that is not a dynamic array, which is also how a foreign
        // link_map layout is caught before it gets dereferenced any further.
        INLINE bool sane(const dyn* d) {
            if (d == 0) return false;
            for (int i = 0; i < 64; ++i) {
                const long t = d[i].tag;
                if (t == OBF_DT_NULL) return true;
                if (t < 0 || t > 0x7ffffffL) return false;
            }
            return false;
        }

        INLINE unsigned hash_basename(const char* path) {
            const char* base = path;
            if (path != 0) {
                for (const char* p = path; *p != 0; ++p)
                    if (*p == '/') base = p + 1;
                return hash_runtime(base);
            }
            return 0;
        }

        INLINE void* finish(unsigned long value, unsigned char info) {
            unsigned long addr = value;
            if ((info & 0xfu) == OBF_STT_IFUNC)
                addr = (unsigned long)((void* (*)())addr)(); // an ifunc stores a resolver
            return (void*)addr;
        }

        INLINE void* find_in_object(const link_map* m, unsigned sym_hash, unsigned elf_hash) {
            const dyn* d = m->dynamic;
            if (!sane(d)) return 0;
            const dyn* d_str = tag(d, OBF_DT_STRTAB);
            const dyn* d_sym = tag(d, OBF_DT_SYMTAB);
            if (d_str == 0 || d_sym == 0) return 0;
            const char* strtab = (const char*)d_str->val;
            const unsigned char* symtab = (const unsigned char*)d_sym->val;
            if (strtab == 0 || symtab == 0) return 0;

            const dyn* d_syment = tag(d, OBF_DT_SYMENT);
            size_t syment = (d_syment != 0 && d_syment->val >= sizeof(sym)) ? (size_t)d_syment->val : sizeof(sym);
            const unsigned long bias = m->load_addr;
            const sym* table = (const sym*)symtab;

            const dyn* d_gnu = tag(d, OBF_DT_GNU_HASH);
            if (d_gnu != 0) {
                const unsigned* g = (const unsigned*)d_gnu->val;
                const unsigned nbuckets = g[0], symoffset = g[1], nbloom = g[2];
                const unsigned* buckets = g + 4 + nbloom * (unsigned)(sizeof(void*) / sizeof(unsigned));
                const unsigned* chains = buckets + nbuckets;
                for (unsigned y = buckets[elf_hash % nbuckets]; y >= symoffset; ++y) {
                    const unsigned c = chains[y];
                    if ((c & ~1u) == elf_hash) {
                        const sym* s = &table[y];
                        if (s->shndx != OBF_SHN_UNDEF && hash_runtime(strtab + s->name) == sym_hash)
                            return finish(s->value + bias, s->info);
                    }
                    if ((c & 1u) != 0u) break; // last entry of this bucket
                }
                return 0;
            }

            const dyn* d_sysv = tag(d, OBF_DT_HASH);
            if (d_sysv != 0) {
                const unsigned* h = (const unsigned*)d_sysv->val;
                const unsigned nbucket = h[0], nchain = h[1];
                const unsigned* buckets = h + 2;
                const unsigned* chains = buckets + nbucket;
                for (unsigned y = buckets[elf_hash % (nbucket ? nbucket : 1u)]; y != 0u && y < nchain; y = chains[y]) {
                    const sym* s = &table[y];
                    if (s->shndx != OBF_SHN_UNDEF && hash_runtime(strtab + s->name) == sym_hash)
                        return finish(s->value + bias, s->info);
                }
            }
            return 0;
        }

        INLINE void* resolve(unsigned mod_hash, unsigned sym_hash, unsigned elf_hash) {
            if ((const void*)_DYNAMIC == 0) return 0;
            // DT_DEBUG is filled in by the dynamic linker with the address of its own
            // r_debug block, which is how the loaded objects are enumerated without
            // depending on the _r_debug symbol being exported.
            const dyn* dbg = tag(_DYNAMIC, OBF_DT_DEBUG);
            if (dbg == 0 || dbg->val == 0) return 0;
            link_map* m = (link_map*)((r_debug*)dbg->val)->map;
            for (int guard = 0; m != 0 && guard < 256; m = m->next, ++guard) {
                if (!sane(m->dynamic)) break;
                if (mod_hash != 0 && hash_basename(m->name) != mod_hash) continue;
                void* found = find_in_object(m, sym_hash, elf_hash);
                if (found != 0) return found;
                if (mod_hash != 0) break;
            }
            return 0;
        }
    }
#endif

    // Resolves one import. The hashes are compile-time constants; the ASCII hints are
    // only ever used by the loader API fallback, and are themselves encrypted.
    template <unsigned ModHash, unsigned SymHash, unsigned ElfHash, unsigned Mask>
    struct import_slot {
        static void* masked_;

        static INLINE void* get(const char* mod_hint, const char* sym_hint) {
#if IMPORT_CACHE
            OBF_UINT cached = (OBF_UINT)(uintptr_t)masked_;
            if (cached != 0u) return (void*)(uintptr_t)(cached ^ (OBF_UINT)Mask);
#endif
            void* p = 0;
#if IMPORT_RESOLVER != OBF_RESOLVER_API
        #if OBF_WINDOWS
            p = pe::resolve(ModHash, SymHash);
        #elif OBF_LINUX
            p = elf::resolve(ModHash, SymHash, ElfHash);
        #endif
#endif
#if IMPORT_RESOLVER != OBF_RESOLVER_MANUAL
            if (p == 0) {
                #if OBF_WINDOWS && !KERNEL_MODE
                    p = (void*)GetProcAddress(GetModuleHandleA(mod_hint), sym_hint);
                #elif OBF_LINUX && !KERNEL_MODE
                    p = dlsym(RTLD_DEFAULT, sym_hint);
                #endif
            }
#endif
            if (p == 0) STACKBRK;
#if IMPORT_CACHE
            masked_ = (void*)(uintptr_t)((OBF_UINT)(uintptr_t)p ^ (OBF_UINT)Mask);
#endif
            return p;
        }
    };

    template <unsigned ModHash, unsigned SymHash, unsigned ElfHash, unsigned Mask>
    void* import_slot<ModHash, SymHash, ElfHash, Mask>::masked_ = 0;
}

#if IMPORT_RESOLVER == OBF_RESOLVER_MANUAL
    // No API fallback, so not even a hint may be stored.
    #define OBF_IMPORT_HINT(s) ((const char*)0)
#else
    #define OBF_IMPORT_HINT(s) OBF(s)
#endif

#if OBF_WINDOWS
    #define CALL_EXPORT(mod, sym, proto, ...) \
        (((proto)obf::import_slot<OBF_HASH_LOWER(mod), OBF_HASH(sym), OBF_ELF_HASH(sym), \
                              (unsigned)RND(1, 0xFFFF)>::get(OBF_IMPORT_HINT(mod), OBF_IMPORT_HINT(sym)))(__VA_ARGS__))
#elif OBF_LINUX
    #define CALL_EXPORT(mod, sym, proto, ...) \
        (((proto)obf::import_slot<OBF_HASH(mod), OBF_HASH(sym), OBF_ELF_HASH(sym), \
                              (unsigned)RND(1, 0xFFFF)>::get(OBF_IMPORT_HINT(mod), OBF_IMPORT_HINT(sym)))(__VA_ARGS__))
#endif

/* Legacy C path: no constexpr, so the names cannot be hashed at compile time. */
#else
    #if OBF_WINDOWS && !KERNEL_MODE
        #define CALL_EXPORT(mod, sym, proto, ...) (((proto)GetProcAddress(GetModuleHandleA(mod), sym))(__VA_ARGS__))
    #elif OBF_LINUX && !KERNEL_MODE
        #define CALL_EXPORT(mod, sym, proto, ...) (((proto)dlsym(RTLD_DEFAULT, sym))(__VA_ARGS__))
    #endif
#endif

/* =============================================================================
 * 13. FAKE SIGNATURES
 *
 * Windows only, and only interesting for shipped binaries: adds sections that
 * Detect-It-Easy and friends attribute to commercial protectors.
 * ============================================================================= */
#if OBF_MSVC
    #define FAKE_SIG(name, section, sig) SECTION(section) volatile static char* name = (char*)(sig)
#else
    #define OBF_FAKE_FILL                                                                        \
        (char)RND(1, 255), (char)RND(1, 255), (char)RND(1, 255), (char)RND(1, 255),             \
        (char)RND(1, 255), (char)RND(1, 255), (char)RND(1, 255), (char)RND(1, 255)
    // The section attribute goes through its own macro on purpose: FAKE_SIG's own
    // parameter is called `section`, and if the attribute were spelled out inline here
    // the parameter would substitute the keyword too, turning section(".vmp0") into
    // ".vmp0"(".vmp0") and failing the compile.
    #define OBF_FAKE_ATTR(sec) __attribute__((used, section(sec)))
    #define FAKE_SIG(name, section, sig)                                                    \
        static volatile char name##_d[] OBF_FAKE_ATTR(section) = { OBF_FAKE_FILL };         \
        static volatile char* name OBF_FAKE_ATTR(section) = (char*)(sig)
#endif

#if FAKE_SIGNATURES && OBF_WINDOWS && !KERNEL_MODE
    #if OBF_MSVC
        #pragma section(".arch")
        #pragma section(".srdata")
        #pragma section(".xpdata")
        #pragma section(".xtls")
        #pragma section(".themida")
        #pragma section(".vmp0")
        #pragma section(".vmp1")
        #pragma section(".vmp2")
        #pragma section(".enigma1")
        #pragma section(".enigma2")
        #pragma section(".dsstext")
    #endif

    // https://enigmaprotector.com
    FAKE_SIG(obf_fake_enigma1, ".enigma1", 0); FAKE_SIG(obf_fake_enigma2, ".enigma2", 0);
    // https://vmpsoft.com
    FAKE_SIG(obf_fake_vmp1, ".vmp0", 0); FAKE_SIG(obf_fake_vmp2, ".vmp1", 0); FAKE_SIG(obf_fake_vmp3, ".vmp2", 0);
    // DENUVO. The upstream list also baited ".xdata", which is dropped here: on x64 that
    // is MSVC's own unwind section, and allocating into it produced LNK4078 (two .xdata
    // sections with different attributes) in a real exception-handling build. The other
    // four names are what the Denuvo detectors actually key on.
    FAKE_SIG(obf_fake_denuvo1, ".arch", 0); FAKE_SIG(obf_fake_denuvo2, ".srdata", 0);
    FAKE_SIG(obf_fake_denuvo4, ".xpdata", 0);
    FAKE_SIG(obf_fake_denuvo5, ".xtls", 0);
    // THEMIDA
    FAKE_SIG(obf_fake_themida1, ".themida", 0);
    // SECUROM
    FAKE_SIG(obf_fake_securom1, ".dsstext", 0);
#if !OBF_MSVC
    static volatile char** const obf_fake_refs[] = {
        &obf_fake_enigma1, &obf_fake_enigma2, &obf_fake_vmp1, &obf_fake_vmp2, &obf_fake_vmp3,
        &obf_fake_denuvo1, &obf_fake_denuvo2, &obf_fake_denuvo4,
        &obf_fake_denuvo5, &obf_fake_themida1, &obf_fake_securom1
    };

    // Addresses only, never the bytes they point at: the bait is on-disk data, and the
    // sections have no readable characteristics, so a real dereference would fault.
    static void obf_fake_touch(void) {
        volatile uintptr_t obf_sink_ = 0u;
        for (volatile size_t obf_i_ = 0;
             obf_i_ < sizeof(obf_fake_refs) / sizeof(obf_fake_refs[0]); ++obf_i_)
            obf_sink_ = (uintptr_t)obf_fake_refs[obf_i_];
        OBF_UNUSED(obf_sink_);
    }

    // A constructor is what makes that reference unremovable.
    __attribute__((used, constructor)) static void obf_fake_init(void) { obf_fake_touch(); }
#endif
#endif

/* =============================================================================
 * 14. INLINE STDLIB
 *
 * String routines compiled into the binary instead of imported, so hooking libc or
 * matching a known call sequence gets nowhere. Deliberately kept before the keyword
 * mutation: these loops must stay ordinary loops.
 * ============================================================================= */

#if INLINE_STD
    static INLINE void inline_strcpy(char* dest, const char* src) {
        while ((*dest++ = *src++))
            ;
    }

    static INLINE unsigned long inline_strtoul(const char* nptr, char** endptr) {
        unsigned long result = 0;
        while (*nptr) {
            char c = *nptr++;
            if (c >= '0' && c <= '9') {
                result = result * 16 + (unsigned long)(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                result = result * 16 + (unsigned long)(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                result = result * 16 + (unsigned long)(c - 'A' + 10);
            } else {
                break;
            }
        }
        if (endptr) {
            *endptr = (char*)nptr;
        }
        return result;
    }

    static INLINE size_t inline_strlen(const char* str) {
        const char* s;
        for (s = str; *s; ++s)
            ;
        return (size_t)(s - str);
    }

    static INLINE char* inline_strncat(char* dest, const char* src, size_t n) {
        char* p = dest;
        while (*p != 0)
            p++;
        while (n > 0 && *src != 0) {
            *p++ = *src++;
            n--;
        }
        *p = 0;
        return dest;
    }

    static INLINE int inline_strcmp(const char* s1, const char* s2) {
        while (*s1 == *s2++)
            if (*s1++ == 0)
                return 0;
        return (*(unsigned char*)s1 - *(unsigned char*)--s2);
    }

    static INLINE int inline_strncmp(const char* s1, const char* s2, size_t n) {
        unsigned char u1, u2;
        while (n-- > 0) {
            u1 = (unsigned char)*s1++;
            u2 = (unsigned char)*s2++;
            if (u1 != u2)
                return u1 - u2;
            if (u1 == '\0')
                return 0;
        }
        return 0;
    }

    static INLINE char* inline_strstr(const char* s, const char* find) {
        char c, sc;
        size_t len;
        if ((c = *find++) != 0) {
            len = inline_strlen(find);
            do {
                do {
                    if ((sc = *s++) == 0)
                        return 0;
                } while (sc != c);
            } while (inline_strncmp(s, find, len) != 0);
            s--;
        }
        return (char*)s;
    }
#endif

/* =============================================================================
 * 15. KEYWORD MUTATION  --  MUST STAY LAST
 *
 * These redefine real C/C++ keywords, which is why they sit at the bottom of the
 * header: everything above, and every header included before obfusheader.h, is
 * compiled as ordinary code. Anything included *after* it is mutated too, so
 * include this header last, or turn off what a file cannot take:
 *
 *   #define CFLOW_BRANCHING 0     // no keyword mutation at all
 *   #define CFLOW_IF 0            // keep cflow, leave `if` alone
 *   #define CFLOW_ASM_JUNK 0      // cflow becomes legal inside constexpr again
 *
 * `if constexpr (...)` is never touched: the macro here is function-like, so it
 * only fires when '(' directly follows 'if'.
 * ============================================================================= */

#if CFLOW_BRANCHING

#if CFLOW_IF
    #define if(...) if (OBF_CF_TRUTH(__VA_ARGS__))
#endif

#if CFLOW_FOR
    // The guard loop runs exactly once and the real header is untouched. The opaque
    // call is parked in the increment rather than the condition, because a condition
    // the compiler cannot prove would make every wrapped `return` look like a path
    // that might not return - which is what -Wreturn-type was reporting inside OBF().
    #define for(...)                                                                                     \
        for (int obf_cf_i_ = 0; obf_cf_i_ < 1; obf_cf_i_++, (void)OBF_CF_MAP((OBF_UINT)OBF_PRED_TRUE))   \
            for (__VA_ARGS__)
#endif

#if CFLOW_WHILE
    #define while(...) while (OBF_CF_TRUTH(__VA_ARGS__))
#endif

#if CFLOW_SWITCH
    #define switch(...) switch (OBF_CF_SWITCH(__VA_ARGS__))
#endif

#if CFLOW_RETURN
#if CFLOW_ASM_JUNK || (__cplusplus >= 202002L)
    // A switch whose only reachable label is default always returns, so no compiler
    // can claim a missing return value - which a guard loop does: -Wreturn-type used to
    // fire on every lambda inside OBF(). `case 0:` exists only because MSVC warns
    // (C4065) about a switch that has a default and no case label at all. Labels are
    // keywords this header never redefines, so the mutation cannot be nested inside
    // the `for` guard below.
    #define return switch ((int)OBF_CF_STEP(OBF_RAND)) case 0: default: return
#else
    // Before C++20 a case label is not allowed inside a constant expression, and any
    // loop wrapper makes clang claim a missing return value (a conditional loop is
    // always treated as escapable). Both are wrong for the constexpr-safe mode, which
    // exists precisely to keep compile-time code compiling, so `return` is left alone
    // there: if/else/for/while/switch still get the full mutation.
#endif
#endif

#if CFLOW_ELSE
    // The trailing `else` rebinds to the fake branch that can never be taken, which
    // keeps the user's else attached to the user's if.
    #define else else if (OBF_CF_TRUTH(OBF_PRED_FALSE)) { ASM_JUNK; } else
#endif

#endif /* CFLOW_BRANCHING */

#if OBF_MSVC
    #pragma warning(pop)
#elif OBF_GNU
    #pragma GCC diagnostic pop
#endif

#endif /* OBFUSHEADER_H */
