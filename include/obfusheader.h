#pragma once
#include <type_traits>

// Settings 
#define THREADLOCAL
#define CFLOW
#define FORCEINLINE

// Force inlining attributes
#ifdef FORCEINLINE
    #if defined(_MSC_VER)
        #define INLINE __forceinline // Visual C++
        #else
        #define INLINE __attribute__((always_inline)) inline // GCC/G++/CLANG
        #endif
    #else
        #define INLINE
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

#ifdef THREADLOCAL
#define OBF(x) (std::decay_t<decltype(x)>) OBF_THREADLOCAL(x)
#else
#define OBF(x) (std::decay_t<decltype(x)>) OBF_NORMAL(x)
#endif

// Call hidding is different on windows and linux (symbol-based)
#if defined(__linux__) || defined(__ANDROID__)
    #include <dlfcn.h>
    #define OBFUSCALL(mtd, def) ((def)(dlsym(RTLD_DEFAULT, OBF(mtd))))
#elif _WIN32
    #include <windows.h>
    #define OBFUSCALL(lib, mtd, def) ((def)(GetProcAddress(LoadLibrary(OBF(lib)), OBF(mtd))))
#endif

namespace obf {
    
    template <class _Ty>
    using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;
    
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
    
    template <class T, int size>
    using determine = typename std::conditional<true, std::remove_all_extents_t<T>, std::remove_all_extents_t<T>>::type;
    
    // Pretty basic cflow to fuck up IDA
    template <class T>
    INLINE T obf_xor(T c, T k, int * stack, int * value, T * result) {
        #ifdef CFLOW
        *value = RND(1, 300),
        *stack = *value;
        goto l_1;
    
        l_increase:
        *result += *stack;
        *stack += 1; // -Wunused-value
    
        l_1:
        if (*stack == *value + 1)
            goto l_increase;
        if (*stack == *value + 2)
            goto l_increase;
        if (*stack == *value + 3)
            goto l_increase;
        if (*stack == *value + 4)
            goto l_increase;
        if (*stack == *value + 0) {
            *result = c ^ k; // real
            goto end;
        }
        if (*stack == *value + 5)
            goto l_increase;
        if (*stack == *value + 6)
            goto l_increase;
        if (*stack == *value + 7)
            goto l_increase;
        end:
        #else
        *result = c ^ k;
        #endif
        return *result;
    }

    template <class T, size_t size, char key>
    class obfuscator {
    public: 
        INLINE constexpr obfuscator(const T * data) {
            for (int i = 0; i < size; i++)
                m_data[i] = data[i] ^ (key + i);
        }
        
        INLINE constexpr obfuscator(const T data) {
            m_data[0] = data ^ key;
        }

        INLINE T * decrypt() {
            if (!decrypted) {
                for (int i = 0; i < size; i++) {
                    m_data[i] = obf_xor<T>(m_data[i], (key + i), &stack, &value, &result);
                }
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
            for (int i = 0; i < size; i++)
                m_data[i] = data.m_data[i];
        }
        
        INLINE T * decrypt() {
            if (!decrypted) {
                for (int i = 0; i < size; i++) {
                    m_data[i] = obf_xor<T>(m_data[i], (key + i), &stack, &value, &result);
                }
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