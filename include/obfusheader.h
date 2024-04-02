#ifndef OBFUSHEADER_H
#define OBFUSHEADER_H

// TODO: find a better way to do this
#define true 1
#define false 0

// Obfusheader settings

// Possible values - THREADLOCAL, NORMAL
// Threadlocal encryption stores the data inside threadlocal space. This can sometimes prevent the compiler from optimizing it away + makes it harder to extract the data
// Normal encryption mode is more performant and stable but a bit less secure
#define ENCRYPT_MODE THREADLOCAL

// Possible values - STATIC, DYNAMIC
// Static call hider stores the function pointers inside a static storager (.data section basically) which is very optimized
// Dynamic call hider inits function pointer arrays in runtime 
#define CALL_HIDE_MODE STATIC

// Possible values - true/false
// Force inline is recommended for better performance and makes it a lot harder to reverse-engineer
#define FORCE_INLINE true

// Possible values true/false
// Control flow affect the performance in a negative way (but not very much)
// It creates garbage flow branches to made the decryption hidden among them
#define CONTROL_FLOW true

// Without forceinline the compiler will mostly ignore inline methods
#if FORCE_INLINE == true
#if defined(_MSC_VER) && !defined(__clang__) 
#define INLINE __forceinline // Visual C++
#else
#define INLINE __attribute__((always_inline)) inline // GCC/G++/CLANG
#endif
#else
#define INLINE inline // Regular inline doesn't always inline
#endif

// __TIME__ && __COUNTER__ both used as a random provider (compile-time) (XX:XX:XX)
#define CTimeSeed ((__COUNTER__ +  __TIME__[0] + __TIME__[1] + __TIME__[3] + __TIME__[4] +\
                                   __TIME__[6] + __TIME__[7]) * 2654435761u)
#define RND(Min, Max) (Min + (CTimeSeed % (Max - Min + 1)))

// Normal & threadlocal modes
#define OBF_KEY_NORMAL(x, type, size, key) []() {\
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

#if ENCRYPT_MODE == THREADLOCAL
#define OBF(x) (meta::decay_t<decltype(x)>) OBF_THREADLOCAL(x)
#else
#define OBF(x) (meta::decay_t<decltype(x)>) OBF_NORMAL(x)
#endif

// Pointer-based call hiding (Crossplatform)
#define DYNAMIC_HIDE_CALL(x, ...) ((decltype(x)) obf::ptr_hider<decltype(x), x, RND(0, 5)>().get())(__VA_ARGS__)
#define STATIC_HIDE_CALL(x, ...) ((decltype(x)) obf::static_storager<decltype(x), x>[OBF(5)])(__VA_ARGS__)
#if CALL_HIDE_MODE == STATIC
#define CALL(x, ...) STATIC_HIDE_CALL(x, __VA_ARGS__)
#elif CALL_HIDE_MODE == DYNAMIC
#define CALL(x, ...) DYNAMIC_HIDE_CALL(x, __VA_ARGS__)
#endif
// Symbol-based call hiding (different for Linux & windows)
#if defined(__linux__) || defined(__ANDROID__)
#include <dlfcn.h>
#define CALL_EXPORT(mtd, def) ((def)(dlsym(RTLD_DEFAULT, OBF(mtd))))
#elif _WIN32
#include <windows.h>
#if defined(_MSC_VER) && !defined(__clang__) // in VisualC++ we cannot encrypt LPCWSTRs for now (ihate windows.h)
#define CALL_EXPORT(lib, mtd, def) ((def)(GetProcAddress(LoadLibrary(lib), mtd)))
#else
#define CALL_EXPORT(lib, mtd, def) ((def)(GetProcAddress(LoadLibrary(OBF(lib)), OBF(mtd))))
#endif
#endif

// Binary watermarking for IDA/GHIDRA that bypasses compiler optimizations
#define WATERMARK(...)\
    const char * data[] = {__VA_ARGS__};\
    for (volatile int i = 0; i < sizeof(data)/sizeof(data[0]); i++)\
        obf::obf_draw(data[i]);\

// This was created so the header works without type_traits (on gcc and other compilers)
// It basically replicates type_traits, it might look scary just skip it
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

    // Decryption with control flow to confuse IDA/GHIDRA
    template <class T, char key, size_t size>
    INLINE void xord(T* data, int* stack, int* value) {
#if CONTROL_FLOW == true
        for (int i = 0; i < size; i++) {
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
            }
        }
#else
        for (int i = 0; i < size; i++)
            data[i] = data[i] ^ static_cast<T>(key + i); // no CONTROL_FLOW (optimized)
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
                xord<T, key, size>(m_data, &stack, &value);
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

        int stack = 0, value = 0;
        T result = NULL;

        bool decrypted = false;
        T m_data[size]{};
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
                xord<T, key, size>(m_data, &stack, &value);
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

        int stack = 0, value = 0;
        T result = NULL;

        bool decrypted = false;
        T m_data[size]{};
    };

    volatile void obf_draw_orig(const char* param) { } // to avoid crashing we assign a real func
    typedef volatile void(*draw_ptr) (const char*); // define a draw function
    volatile draw_ptr obf_draw = reinterpret_cast<volatile void(*)(const char*)>(obf_draw_orig); // assign draw_orig to avoid segfault

    volatile void main_decoy() {
        // Message for crackers ;)
        WATERMARK("Stop reversing the program",
                  "Reconsider your life choices",
                  "And go touch some grass", "");
    }

    // Fake decoy functions to hide the original one (for call hiding)
    void decoy_1() { main_decoy(); }
    void decoy_2() { main_decoy(); }
    void decoy_3() { main_decoy(); }
    void decoy_4() { main_decoy(); }
    void decoy_5() { main_decoy(); }
    void decoy_6() { main_decoy(); }
    void decoy_7() { main_decoy(); }
    void decoy_8() { main_decoy(); }
    void decoy_9() { main_decoy(); }
    void decoy_10() { main_decoy(); }

    // We cannot randomize the real function index while using static storager sadly
    // So it's just a hardcoded index, for example 5 (like here)
    template <typename T, T real>
    T static_storager[] = {
        reinterpret_cast<T>(&decoy_1),
        reinterpret_cast<T>(&decoy_2),
        reinterpret_cast<T>(&decoy_3),
        reinterpret_cast<T>(&decoy_4),
        reinterpret_cast<T>(&decoy_5),
        reinterpret_cast<T>(real),
        reinterpret_cast<T>(&decoy_6),
        reinterpret_cast<T>(&decoy_7),
        reinterpret_cast<T>(&decoy_1),
        reinterpret_cast<T>(&decoy_2),
        reinterpret_cast<T>(&decoy_3),
        reinterpret_cast<T>(&decoy_4),
        reinterpret_cast<T>(&decoy_5),
        reinterpret_cast<T>(&decoy_1),
        reinterpret_cast<T>(&decoy_2),
        reinterpret_cast<T>(&decoy_3)
    };

    // In dynamic case we can actually randomize the index
    template <typename T, T real, int index>
    class ptr_hider {
    public:
        INLINE ptr_hider() {
            real_index = OBF(index);
            START:
            int storager_size = sizeof(storager) / sizeof(storager[0]);
            if (real_index >= 0 && real_index < storager_size) {
                storager[real_index] = real;
                goto END;
            }
            if (real_index + 1 >= 0 && real_index + 1 < storager_size) {
                storager[real_index + 1] = reinterpret_cast<T>(&decoy_1);
                goto START;
            }
            if (real_index + 2 >= 0 && real_index + 2 < storager_size) {
                storager[real_index + 2] = reinterpret_cast<T>(&decoy_2);
                goto END;
            }
            if (real_index + 2 >= 0 && real_index + 3 < storager_size) {
                storager[real_index + 3] = reinterpret_cast<T>(&decoy_3);
                goto START;
            }
            if (real_index + 2 >= 0 && real_index + 4 < storager_size) {
                storager[real_index + 4] = reinterpret_cast<T>(&decoy_4);
                goto END;
            }
            if (real_index + 2 >= 0 && real_index + 5 < storager_size) {
                storager[real_index + 5] = reinterpret_cast<T>(&decoy_5);
                goto START;
            }
            END: return;
        }

        T get() {
            return storager[real_index];
        }

        int real_index = 0;
        T storager[5];
    };
}

#endif