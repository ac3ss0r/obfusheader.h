#pragma once

// Settings (Just comment out whatever you need)
#define THREAD_LOCAL
#define CFLOW
#define FORCE_INLINE

// Without forceinline the compiler will mostly ignore inline methods
#ifdef FORCE_INLINE
    #if defined(_MSC_VER)
        #define INLINE __forceinline // Visual C++
    #else
        #define INLINE __attribute__((always_inline)) inline // GCC/G++/CLANG
    #endif
#else
    #define INLINE inline // Regular inline doesn't always inline
#endif

// __TIME__ && __COUNTER__ both used as a random provider (compile-time)
// 00:XX:XX -> __TIME__[3], __TIME__[4], __TIME__[6], __TIME__[7] 
#define CTimeSeed ((__COUNTER__ ^ __TIME__[3]) * (__COUNTER__ ^ __TIME__[4]) +\
                  (__COUNTER__ ^ __TIME__[6]) * (__COUNTER__ ^ __TIME__[7]))
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

#ifdef THREAD_LOCAL
    #define OBF(x) (meta::decay_t<decltype(x)>) OBF_THREADLOCAL(x)
#else
    #define OBF(x) (meta::decay_t<decltype(x)>) OBF_NORMAL(x)
#endif

// Call hidding is different on windows and linux (symbol-based)
#if defined(__linux__) || defined(__ANDROID__)
    #include <dlfcn.h>
    #define OBFUSCALL(mtd, def) ((def)(dlsym(RTLD_DEFAULT, OBF(mtd))))
#elif _WIN32
    #include <windows.h>
    #define OBFUSCALL(lib, mtd, def) ((def)(GetProcAddress(LoadLibrary(OBF(lib)), OBF(mtd))))
#endif

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
    
    typedef integral_constant<bool,false> false_type;
    typedef integral_constant<bool,true> true_type;
    
    // primary template
    template<class>
    struct is_function : false_type {};
    
    // specialization for regular functions
    template<class Ret, class... Args>
    struct is_function<Ret(Args...)> : true_type {};
    
    // specialization for variadic functions such as std::printf
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...)> : true_type {};
    
    // specialization for function types that have cv-qualifiers
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) volatile> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const volatile> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) const> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) volatile> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) const volatile> : true_type {};
    
    // specialization for function types that have ref-qualifiers
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) &> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const &> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) volatile &> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const volatile &> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) &> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) const &> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) volatile &> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) const volatile &> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) &&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const &&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) volatile &&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...) const volatile &&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) &&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) const &&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) volatile &&> : true_type {};
    template<class Ret, class... Args>
    struct is_function<Ret(Args...,...) const volatile &&> : true_type {};
    
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
    auto try_add_pointer(int) -> type_identity<typename remove_reference<T>::type*>;  // usual case
    template<class T>
    auto try_add_pointer(...) -> type_identity<T>;  // unusual case (cannot form std::remove_reference<T>::type*)
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
    INLINE void xord(T * data, int * stack, int * value) {
        #ifdef CFLOW
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
                data[i] = data[i] ^ (key + i); // real
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
            data[i] = data[i] ^ (key + i); // no cflow
        #endif
    }

    template <class T, size_t size, char key>
    class obfuscator {
    public: 
        INLINE constexpr obfuscator(const T * data) {
            for (int i = 0; i <size; i++)
                m_data[i] = data[i] ^ (key + i);
        }
        
        INLINE constexpr obfuscator(const T data) {
            m_data[0] = data ^ key;
        }

        INLINE T * decrypt() {
            if (!decrypted) {
                xord<T, key, size>(m_data, &stack, &value);
            }
            decrypted = true;
            return m_data;
        }
        
        INLINE operator T * () {
            return decrypt();
        }
        
        INLINE operator T () {
            return decrypt()[0];
        }
    
        int stack = 0, value = 0;
        T result = NULL;
        
        bool decrypted = false;
        T m_data[size] {};
    };
    
    template <class T, size_t size, char key>
    class decryptor {
    public:
        INLINE decryptor(const obfuscator<T, size, key> data) {
            for (int i = 0; i <size; i++)
                m_data[i] = data.m_data[i];
        }
        
        INLINE T * decrypt() {
            if (!decrypted) {
                xord<T, key, size>(m_data, &stack, &value);
            }
            decrypted = true;
            return m_data;
        }
        
        INLINE operator T * () {
            return decrypt();
        }
        
        INLINE operator T () {
            return decrypt()[0];
        }
        
        int stack = 0, value = 0;
        T result = NULL;
        
        bool decrypted = false;
        T m_data[size] {};
    };
}