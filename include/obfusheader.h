#ifndef OBFUSHEADER_H
#define OBFUSHEADER_H

/*
           __      ____                    __                       __                     __
  ____    / /_    / __/  __  __   _____   / /_   ___   ____ _  ____/ /  ___    _____      / /_
 / __ \  / __ \  / /_   / / / /  / ___/  / __ \ / _ \ / __ `/ / __  /  / _ \  / ___/     / __ \
/ /_/ / / /_/ / / __/  / /_/ /  (__  )  / / / //  __// /_/ / / /_/ /  /  __/ / /     _  / / / /
\____/ /_.___/ /_/     \__,_/  /____/  /_/ /_/ \___/ \__,_/  \__,_/   \___/ /_/     (_)/_/ /_/

C/C++ compile-time obfuscation header for C/C++ without any external dependencies made by ac3ss0r
Visit https://github.com/ac3ss0r/obfusheader.h for configuration tips & more information
*/

#pragma region CONSTANTS
    #define NORMAL      0
    #define THREADLOCAL 1
#pragma endregion CONSTANTS

#pragma region CONFIG
    // C++ only features
    #define CONST_ENCRYPTION            1
    #define CONST_ENCRYPT_MODE          NORMAL // NORMAL & THREADLOCAL
    #define CFLOW_CONST_DECRYPTION      1
    // C & C++ features
    #define CFLOW_BRANCHING             1
    #define INDIRECT_BRANCHING          1
    #define FAKE_SIGNATURES             1
    #define INLINE_STD                  1
#pragma endregion CONFIG

#pragma region OBFUSCATION

// clang is pretending to be other compilers :warning: !!!
#if defined(_MSC_VER) && !defined(__clang__) && !defined(__llvm__) 
    #define _MSVC //real visual C++
#elif defined (__GNUC__) || defined(__clang__) || defined(__llvm__)
    #define _GNUC
#elif defined(__TINYC__)
    #define _TCC
#else
    #define _COMPILER_UNKNOWN
#endif

// Detect target arch, os & compiler via all existing definitions

#if defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    #define x86_32
#elif defined(__x86_64__) || defined(_M_X64)
    #define x86_64
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define ARM64
#elif defined(_M_ARM)
    #define ARM
#else
    #define _ARCH_UNKNOWN
#endif

#if defined(_WIN64) || defined(WIN64) || defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    #define _WINDOWS
#elif  defined(__linux__) || defined(__ANDROID__)
    #define _LINUX // android is linux tbh
#elif defined(__APPLE__)
    #define _APPLE // stinky
#else
    #define _OS_UNKNOWN
#endif

#ifdef __TINYC__ 
    #error Obfusheader doesn't support TCC at the moment :broken_heart:
#endif
#if !defined(OBF_UNSUPPORTED) && !defined(_MSC_VER) && !defined(__clang__)
    #error Your compiler most likely isn't supported by obfusheader.h. If you're sure it's supported use #define OBF_UNSUPPORTED.
#endif
#ifdef _MSC_VER
    #pragma warning(disable:4996) // womp womp bored karma
#endif

// for call hiding & drm modules
#if defined(_WINDOWS)
    #include <windows.h>
#elif defined(_LINUX) || defined(_ANDROID)
    #include <dlfcn.h>  
#endif

// Without forceinline the compiler will mostly ignore inline methods
#if defined(_MSC_VER)
    #define INLINE __forceinline // Visual C++
#else
    #define INLINE __attribute__((always_inline)) // GCC/G++/CLANG
#endif

// Prevents functions from inlining forcefully
#if defined(_MSC_VER)
    #define NOINLINE __declspec(noinline)
#else 
    #define NOINLINE __attribute__((noinline))
#endif

// Create custom sections on both clang & msc++
#if defined(_MSC_VER)
    #define SECTION(x) __declspec(allocate(x))
#else
    #define SECTION(x) __attribute__((section(x)))
#endif

#define FAKE_SIG(name, section, sig) \
    SECTION(section) volatile char * name = (char*)sig;

// Funny. Only makes sense for windows & PE files (Tricks https://github.com/horsicq/Detect-It-Easy)
#if FAKE_SIGNATURES && defined(_WINDOWS)
    #ifdef _MSC_VER
        #pragma section(".arch")
        #pragma section(".srdata")
        #pragma section(".xpdata")
        #pragma section(".xdata")
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
    FAKE_SIG(_enigma1, ".enigma1", 0); FAKE_SIG(_enigma2, ".enigma2", 0);
    // https://vmpsoft.com (opensource)
    FAKE_SIG(_vmp1, ".vmp0", 0); FAKE_SIG(_vmp2, ".vmp1", 0); FAKE_SIG(_vmp3, ".vmp2", 0);
    // DENUVO
    FAKE_SIG(_denuvo1, ".arch", 0); FAKE_SIG(_denuvo2, ".srdata", 0); FAKE_SIG(_denuvo3, ".xdata", 0);
    FAKE_SIG(_denuvo4, ".xpdata", 0); FAKE_SIG(_denuvo5, ".xtls", "\x64\x65\x6E\x75\x76\x6F\x5F\x61\x74\x64\x00\x00\x00\x00\x00\x00");
    // THEMIDA
    FAKE_SIG(_themida1, ".themida", 0);
    // SECUROM
    FAKE_SIG(_securom1, ".dsstext", 0);
#endif

// __TIME__, __LINE__, __COUNTER__ are used for fully compile-time random
#ifdef __cplusplus // using constexpr allows us to avoid embeding XX:XX:XX into the binary
    constexpr int CTime = __TIME__[0] + __TIME__[1] + __TIME__[3] + __TIME__[4] + __TIME__[6] + __TIME__[7];
    #define CTimeSeed ((__COUNTER__ + CTime) * 2654435761u)
#else // for C we cannot base it on __TIME__, since there's no constexpr, or XX:XX:XX will be added to the binary
    #define CTimeSeed ((__COUNTER__ + __LINE__) * 2654435761u)
#endif
#define RND(Min, Max) (Min + (CTimeSeed % (Max - Min + 1)))

#define _RND RND(1, 10)
#define _TRUE ((((_9 + __7() + ((_RND * __2()) * __0()))) / _8) - _1)
#define _FALSE ((_3 + __6() + ((_RND * __3()) * _0)) - __9())

// Use stored in static memory essential bytes for hardcoded cflow blocks & expressions
#if CFLOW_CONST_DECRYPTION || CFLOW_BRANCHING
    volatile char _a = 'a', _b = 'b', _c = 'c', _d = 'd', _e = 'e', _f = 'f', _g = 'g', _h = 'h', _i = 'i', _j = 'j', _k = 'k', _l = 'l', _m = 'm', _n = 'n', _o = 'o', _p = 'p',
                  _q = 'q', _r = 'r', _s = 's', _t = 't', _u = 'u', _v = 'v', _w = 'w', _x = 'x', _y = 'y', _z = 'z', _S = 'S', _L = 'L', _A = 'A', _I = 'I', _D = 'D', _P = 'P';
    volatile char _0 = 0, _1 = 1, _2 = 2, _3 = 3, _4 = 4, _5 = 5, _6 = 6, _7 = 7, _8 = 8, _9 = 9;
    // Same trick with NOINLINED functions (proxies)
    NOINLINE char __0() { return 0; } NOINLINE char __1() { return 1; } NOINLINE char __2() { return 2; } NOINLINE char __3() { return 3; } NOINLINE char __4() { return 4; }
    NOINLINE char __5() { return 5; } NOINLINE char __6() { return 6; } NOINLINE char __7() { return 7; } NOINLINE char __8() { return 8; } NOINLINE char __9() { return 9; }
#endif

// Easily build hardcoded control-flow protection blocks
#define BLOCK_COND(cond, block) if (cond) { block; }
#define BLOCK_TRUE(block) BLOCK_COND(_TRUE, block)
#define BLOCK_FALSE(block) BLOCK_COND(_FALSE, block)

// This is s a technique allowing to completely break IDA Decompiler
#if INDIRECT_BRANCHING
    #ifdef x86_32 
    #ifdef _MSC_VER
        #define INDIRECT_BRANCH\
                                __asm __volatile { \
                                    __asm xor eax, eax \
                                    __asm jz loc_real \
                                    __asm _emit 0x00 \
                                    __asm loc_real: \
                                }
    #else // clang
        #define INDIRECT_BRANCH\
                                asm volatile(\
                                    "xor %eax, %eax\n"\
                                    "jz 1f\n"\
                                    ".byte 0x00\n"\
                                    "1:");
    #endif
    #elif defined(x86_64)
        #ifndef _MSC_VER
            #define INDIRECT_BRANCH\
                                asm volatile(\
                                    "xor %%rax, %%rax\n"\
                                    "jz 1f\n"\
                                    ".byte 0x00\n"\
                                    "1:" : : : "rax");
        #else // Visual C++ doesn't support x64 inline asm (omw to kms)
            #define INDIRECT_BRANCH
        #endif
    #else // TODO: add more arches (arm64, arm, etc)
        #define INDIRECT_BRANCH
    #endif
#else
    #define INDIRECT_BRANCH // nothing
#endif

// Very funny
#define SEGFAULT int_proxy(*(int*)RND(0, 0x7FFFFF))

// Control flow base (will be inlined upon compilation). Includes indirect branching to break decompilers
#if CFLOW_CONST_DECRYPTION || CFLOW_BRANCHING
    volatile INLINE int int_proxy(double val) {
        INDIRECT_BRANCH;
        volatile double a = val * (_7 - (_3 * 2));
    loc_start:
        BLOCK_TRUE(
            BLOCK_FALSE( 
                for (int i = 0; i < RND(1, 20); i++) {
                    if (a + i == __0()) {
                        a += i & 0;
                        goto loc_start;
                    } else if (a + i == __1()) {
                        a += i & 1;
                    } else {
                        if (RND(0, 1)) {
                            goto loc_fake;
                        } else {
                            goto loc_middle;
                        }
                    }
                    return a + i;
                loc_middle:
                    if (RND(0, 1)) {
                        goto loc_end;
                    } else {
                        goto loc_start;
                    }
                }
            goto loc_start;
            );
        goto loc_end;
        );
    loc_end:
        if (_RND) {
            return a * _TRUE;
        } else {
            goto loc_fake;
        }
    loc_fake:
        return _RND;
    }
#endif

// Watermarking for IDA/GHIDRA decompilers
void obfusheader_watermark_hook(const char* param) {} // to avoid crashing we assign a real func
typedef volatile void(*draw_ptr) (const char*); // define a draw function
volatile draw_ptr obfusheader_watermark_orig = (draw_ptr)obfusheader_watermark_hook; // assign draw_orig to avoid segfault

// Binary watermarking for IDA/GHIDRA that bypasses compiler optimizations
#define WATERMARK(...)\
    const char * data[] = {__VA_ARGS__};\
    for (volatile int i = 0; i < sizeof(data)/sizeof(data[0]); i++)\
        obfusheader_watermark_orig(data[i]);\

volatile void obfusheader_decoy_main() {
    // Message for crackers ;)
    WATERMARK("Stop reversing the binary",
                "Reconsider your life choices",
                    "And go touch some grass", 0);
}

// Fake decoy functions to hide the original one (for call hiding)
void obfusheader_decoy_1() { obfusheader_decoy_main(); }
void obfusheader_decoy_2() { obfusheader_decoy_main(); }
void obfusheader_decoy_3() { obfusheader_decoy_main(); }
void obfusheader_decoy_4() { obfusheader_decoy_main(); }
void obfusheader_decoy_5() { obfusheader_decoy_main(); }
void obfusheader_decoy_6() { obfusheader_decoy_main(); }
void obfusheader_decoy_7() { obfusheader_decoy_main(); }
void obfusheader_decoy_8() { obfusheader_decoy_main(); }
void obfusheader_decoy_9() { obfusheader_decoy_main(); }
void obfusheader_decoy_10() { obfusheader_decoy_main(); }

// C++ only features
#ifdef __cplusplus 
// C++ doesn't allow xor-ing bools so this is required for proper encryption. If this causes problems then remove and don't encrypt bools!!!
#define true 1
#define false 0

// Normal & threadlocal encryption modes
#define OBF_KEY_NORMAL(x, type, size, key) []() -> obf::obfuscator<type, size, key> {\
    constexpr static auto data = obf::obfuscator<type, size, key>(x);\
    return data;\
}()
#define OBF_KEY_THREADLOCAL(x, type, size, key) []() -> obf::decryptor<type, size, key>& {\
    constexpr static auto data = obf::obfuscator<type, size, key>(x);\
    thread_local auto decryptor = obf::decryptor<type, size, key>(data);\
    return decryptor;\
}()
#define OBF_NORMAL(x) OBF_KEY_NORMAL(x, obf::clean_type<decltype(obf::gettype(x))>, obf::getsize(x), (char)RND(1, 255))
#define OBF_THREADLOCAL(x) OBF_KEY_THREADLOCAL(x, obf::clean_type<decltype(obf::gettype(x))>, obf::getsize(x), (char)RND(1, 255))

#if CONST_ENCRYPTION
    #if CONST_ENCRYPT_MODE == NORMAL
        #define OBF(x) (meta::decay_t<decltype(x)>) OBF_NORMAL(x)
    #elif CONST_ENCRYPT_MODE == THREADLOCAL
        #define OBF(x) (meta::decay_t<decltype(x)>) OBF_THREADLOCAL(x)
    #endif
#else
    #define OBF(x) x
#endif

// Pointer-based call hiding (Crossplatform)
#define HIDE_PTR_I(ptr, index) obf::FunctionPtrHider<decltype(ptr), 10, index, ptr, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9>::shuffled_arr[OBF(index)]
#define HIDE_PTR(ptr) HIDE_PTR_I(ptr, RND(0, 9))
#define CALL(ptr, ...) (HIDE_PTR(ptr)(__VA_ARGS__))

// Symbol-based call hiding (different for Linux & windows)
#if defined(__linux__) || defined(__ANDROID__)
    #define CALL_EXPORT(mtd, def, ...) (((def)dlsym(RTLD_DEFAULT, OBF(mtd)))(__VA_ARGS__))
#elif defined(_WINDOWS)
    #define CALL_EXPORT(lib, mtd, def, ...) (((def)GetProcAddress(GetModuleHandleA(lib), mtd))(__VA_ARGS__))
#endif

// This was created so the header works without type_traits (on gcc and other compilers)
// Also since type_traits gets updated at newer C++ versions this will help avoiding problems
namespace meta {

    template<class T, T v>
    struct integral_constant {
        static constexpr T value = v;
        using value_type = T;
        using type = integral_constant; // using injected-class-name
        constexpr operator value_type() const noexcept { return value; }
        constexpr value_type operator()() const noexcept { return value; } // since c++14
    };

    typedef integral_constant<bool, false> false_type;
    typedef integral_constant<bool, true> true_type;

    // primary template
    template<class>
    struct is_function : false_type {};

    // specialization for regular functions
    template<class Ret, class... Args>
    struct is_function<Ret(Args...)> : true_type {};

    // specialization for variadic functions such as std::printf
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...)> : true_type {};

    // specialization for function types that have cv-qualifiers
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) volatile> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const volatile> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) volatile> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const volatile> : true_type {};

    // specialization for function types that have ref-qualifiers
    template<class Ret, class... Args>
    struct is_function<Ret(Args...)&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) volatile&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const volatile&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...)&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) volatile&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const volatile&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...)&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) volatile&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const volatile&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...)&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) volatile&&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args..., ...) const volatile&&> : true_type {};

    template<class T>
    struct is_array : false_type {};
    template<class T>
    struct is_array<T[]> : true_type {};
    template<class T, size_t N>
    struct is_array<T[N]> : true_type {};

    template<class T>
    struct remove_extent { using type = T; };
    template<class T>
    struct remove_extent<T[]> { using type = T; };
    template<class T, size_t N>
    struct remove_extent<T[N]> { using type = T; };

    template<class T> struct remove_reference { typedef T type; };
    template<class T> struct remove_reference<T&> { typedef T type; };
    template<class T> struct remove_reference<T&&> { typedef T type; };

    template<class T> struct remove_cv { typedef T type; };
    template<class T> struct remove_cv<const T> { typedef T type; };
    template<class T> struct remove_cv<volatile T> { typedef T type; };
    template<class T> struct remove_cv<const volatile T> { typedef T type; };

    template<class T> struct remove_const { typedef T type; };
    template<class T> struct remove_const<const T> { typedef T type; };

    template<class T> struct remove_volatile { typedef T type; };
    template<class T> struct remove_volatile<volatile T> { typedef T type; };

    template<class T>
    struct remove_all_extents { typedef T type; };
    template<class T>
    struct remove_all_extents<T[]> {
        typedef typename remove_all_extents<T>::type type;
    };
    template<class T, size_t N>
    struct remove_all_extents<T[N]> {
        typedef typename remove_all_extents<T>::type type;
    };

    template<bool B, class T, class F>
    struct conditional { using type = T; };
    template<class T, class F>
    struct conditional<false, T, F> { using type = F; };

    template<class T>
    struct type_identity { using type = T; }; // or use std::type_identity (since C++20)
    template<class T>
    auto try_add_pointer(int)->type_identity<typename remove_reference<T>::type*>;  // usual case
    template<class T>
    auto try_add_pointer(...)->type_identity<T>;  // unusual case (cannot form std::remove_reference<T>::type*)
    template<class T>
    struct add_pointer : decltype(try_add_pointer<T>(0)) {};

    // Helpers from C++14 
    template<class T>
    using remove_cv_t = typename remove_cv<T>::type;
    template<class T>
    using remove_const_t = typename remove_const<T>::type;
    template<class T>
    using remove_volatile_t = typename remove_volatile<T>::type;
    template<class T>
    using remove_reference_t = typename remove_reference<T>::type;
    template<class T>
    using remove_all_extents_t = typename remove_all_extents<T>::type;

    template<class T>
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

    template<class T>
    using decay_t = typename decay<T>::type;
}

namespace obf {

    template <class _Ty>
    using clean_type = typename meta::remove_const_t<meta::remove_reference_t<_Ty>>;

    template <typename T, T value>
    static T ensure_threadlocal() { thread_local T v = value; return v; }

    template <typename T, T value>
    static constexpr T ensure_constexpr() { return value; }

    template<typename T, int size>
    constexpr size_t getsize(const T(&)[size]) { return size; }

    template<typename T>
    constexpr size_t getsize(T) { return 1; }

    template<typename T, size_t size>
    constexpr static T gettype(const T(&)[size]);

    template<typename T>
    constexpr static T gettype(T);

    #define XOR(x, y) (x + y - (2 * (x & y)))

    // Decryption with control flow to confuse IDA/GHIDRA
    template <class T, char key, size_t size>
    INLINE void xord(T* data) {
        #if CFLOW_CONST_DECRYPTION
        for (int i = 0; i < size; i++) {
            BLOCK_FALSE(
                data[i] = data[i] ^ int_proxy(key + 1);
            );
            BLOCK_TRUE(
                BLOCK_FALSE(
                    data[i] = data[i] ^ int_proxy(key + 2);
                );
                BLOCK_FALSE(
                    data[i] = data[i] ^ int_proxy(key + 3);
                );
                data[i] = XOR(data[i], static_cast<T>(int_proxy(key + i))); // real
            );
            BLOCK_FALSE(
                data[i] = data[i] ^ int_proxy(key + 4);
            );

            /* OLD deprecated control flow

             goto l_1;
             l_increase:
             *stack += 1; // -Wunused-value

             l_1:
             if (*stack == *value + 1) {
                 data[i] = data[i] ^ (*value + 1);
                 goto l_increase;
             }
             if (*stack == *value + 2) {
                 data[i] = data[i] ^ (*value + 2);
                 goto l_increase;
             }
             if (*stack == *value + 0) {
                 data[i] = data[i] ^ static_cast<T>(key + i); // real
                 continue;
             }
             if (*stack == *value + 4) {
                 data[i] = data[i] ^ (*value + 3);
                 goto l_increase;
             }
             if (*stack == *value + 5) {
                 data[i] = data[i] ^ (*value + 4);
                 goto l_increase;
             }*/
        }
        #else
        for (volatile int i = 0; i < size; i++)
            data[i] = data[i] ^ static_cast<T>(key + i); // no cflow (optimized+unsafe)
        #endif
    }

    template <class T, size_t size, char key>
    class obfuscator {
    public:
        INLINE constexpr obfuscator(const T* data) {
            for (int i = 0; i < size; i++)
                m_data[i] = data[i] ^ static_cast<T>(key + i);
        }

        INLINE constexpr obfuscator(const T data) {
            m_data[0] = data ^ key;
        }

        INLINE T* decrypt() {
            if (!decrypted) {
                xord<T, key, size>(m_data);
            }
            decrypted = true;
            return m_data;
        }

        INLINE operator T* () {
            return decrypt();
        }

        INLINE operator T () {
            return decrypt()[0];
        }

        T m_data[size]{};
        bool decrypted = false;
    };

    template <class T, size_t size, char key>
    class decryptor {
    public:
        INLINE decryptor(const obfuscator<T, size, key> data) {
            for (int i = 0; i < size; i++)
                m_data[i] = data.m_data[i];
        }

        INLINE T* decrypt() {
            if (!decrypted) {
                xord<T, key, size>(m_data);
            }
            decrypted = true;
            return m_data;
        }

        INLINE operator T* () {
            return decrypt();
        }

        INLINE operator T () {
            return decrypt()[0];
        }


        T m_data[size]{};
        bool decrypted = false;
    };

    // Hiding function pointers & masking calls. New method. very op

    template <typename T, int N, int real_index, T real_value, int index>
    constexpr T select_func() {
        T funcs[N + 1] = {
            reinterpret_cast<T>(obfusheader_decoy_1), reinterpret_cast<T>((char*)_RND), reinterpret_cast<T>(obfusheader_decoy_2), reinterpret_cast<T>(obfusheader_decoy_3),
            reinterpret_cast<T>((char*)_RND), reinterpret_cast<T>(0), reinterpret_cast<T>((char*)_RND),
            reinterpret_cast<T>(obfusheader_decoy_5), reinterpret_cast<T>((char*)_RND), reinterpret_cast<T>((char*)_RND), reinterpret_cast<T>(real_value)
        };
        if (index == real_index)  // Index of the real func
            return funcs[N];
        return reinterpret_cast<T>(funcs[index]);
    }

    template <typename T, int N, int real_index, T real_value, int... indices>
    struct FunctionPtrHider {
        static T shuffled_arr[N];
    };

    template <typename T, int N, int real_index, T real_value, int... indices>
    T FunctionPtrHider<T, N, real_index, real_value, indices...>::shuffled_arr[N] = {
        select_func<T, N, real_index, real_value, indices>()...
    };
}
#else // C doesn't support compile-time encryption cause no constexpr sadly :( So we just implement it like this & disable everything
    #define OBF(x) x
    #define CALL(ptr, ...) (ptr)(__VA_ARGS__)
    #define HIDE_PTR(ptr) (ptr)
    // Symbol - based call hiding(different for Linux& windows)
    #if defined(__linux__) || defined(__ANDROID__)
    #define CALL_EXPORT(mtd, def) ((def)(dlsym(RTLD_DEFAULT, OBF(mtd))))
    #elif defined(_WINDOWS)
    #define CALL_EXPORT(lib, mtd, def) ((def)(GetProcAddress(LoadLibraryA(lib), mtd)))
    #endif
#endif

// Obviously affects performance. Use with caution!
#if CFLOW_BRANCHING 
    #define if(x) if (int_proxy((long long)(x)) * _TRUE && (_RND * _FALSE + _TRUE))
    #define while(x) while(int_proxy((long long)(x)) * _TRUE && _RND + _FALSE)
    #define switch(x) switch(int_proxy((long long)(x)) * _TRUE && _RND + _FALSE)
    #define for(x) for(x && int_proxy(_FALSE) * _TRUE)
    #define return for (int _i = 0; _i < RND(1, 100); _i++) return
    // This will hurt (Some compilers don't allow this, disable if fails)
    #define else else\
                        BLOCK_FALSE(\
                            int_proxy(_RND);\
                            BLOCK_TRUE(\
                                int_proxy(_RND);\
                            )\
                        ) else
#endif

#pragma endregion OBFUSCATION

#pragma region MODULES
#if INLINE_STD

    INLINE void inline_strcpy(char* dest,
        const char* src) {
        while ((*dest++ = *src++));
    }

    INLINE unsigned long inline_strtoul(const char* nptr, char** endptr) {
        unsigned long result = 0;
        while (*nptr) {
            char c = *nptr++;
            if (c >= '0' && c <= '9') {
                result = result * 16 + (c - '0');
            } else if (c >= 'a' && c <= 'f') {
                result = result * 16 + (c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                result = result * 16 + (c - 'A' + 10);
            } else {
                break;
            }
        }
        if (endptr) {
            *endptr = (char*)nptr;
        }
        return result;
    }

    INLINE size_t inline_strlen(const char* str) {
        const char* s;
        for (s = str; *s; ++s);
        return (s - str);
    }

    INLINE char* inline_strncat(char* dest,
        const char* src, size_t n) {
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

    INLINE int inline_strcmp(const char* s1, const char* s2) {
        while (*s1 == *s2++)
            if (*s1++ == 0)
                return (0);
        return (*(unsigned char*)s1 -
            *(unsigned char*) --s2);
    }

    INLINE int inline_strncmp(const char* s1,
        const char* s2, size_t n) {
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

    INLINE char* inline_strstr(const char* s,
        const char* find) {
        char c, sc;
        size_t len;
        if ((c = *find++) != 0) {
            len = inline_strlen(find);
            do {
                do {
                    if ((sc = *s++) == 0)
                        return (NULL);
                } while (sc != c);
            } while (inline_strncmp(s, find, len) != 0);
            s--;
        }
        return ((char*)s);
    }

#endif
#pragma endregion MODULES

#endif