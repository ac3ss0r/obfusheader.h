#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>
#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <dlfcn.h>
#endif
#define CFLOW_BRANCHING 0
#include "../include/obfusheader.h"

static int failures;
static NOINLINE int hidden_target(int value) { return value + 17; }
static int concurrent_hidden_call(int value) { return CALL(&hidden_target, value); }
#define CHECK(x) do { if (!(x)) { ++failures; std::printf("FAILED: %s\n", #x); } } while (0)

#if CONST_ENCRYPT_MODE == OBF_MODE_THREADLOCAL
static const char* tls_text() { return OBF("TLS lifetime marker"); }
#endif

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    static constexpr char16_t utf16[] = u"typed UTF16";
    auto utf16_vault = MAKEOBF(utf16);
    const char16_t* decoded_utf16 = utf16_vault;
    for (unsigned i = 0; i < sizeof(utf16) / sizeof(*utf16); ++i) CHECK(decoded_utf16[i] == utf16[i]);
    static constexpr bool boolean_array[] = { true, false, true };
    auto bool_vault = MAKEOBF(boolean_array);
    bool* decoded_bool = bool_vault;
    CHECK(decoded_bool[0] && !decoded_bool[1] && decoded_bool[2]);
    decoded_bool[0] = false;
    CHECK(!static_cast<bool*>(bool_vault)[0]);
    static_assert(obf::hash_gnu("printf") == 0x156b2bb8u, "GNU hash vector");
    static_assert(obf::hash_elf("printf") == 0x077905a6u, "SYSV hash vector");
    static_assert(obf::key_at<uint64_t>(1u, 0u) != obf::key_at<uint64_t>(257u, 0u), "key must not truncate to a byte");
#if VAULT_CHECK
    // Mutate the object's byte representation, as an on-disk payload patch would.
    using test_vault = obf::vault<char, uint8_t, 6, 0x12345678u, 2, 1, 99u, 3>;
    constexpr test_vault original("probe");
    auto patched = original;
    reinterpret_cast<unsigned char*>(&patched)[6] ^= 1u;
    const char* rejected = patched;
    for (int i = 0; i < 6; ++i) CHECK(rejected[i] == 0);
    CHECK(static_cast<char*>(patched)[0] == 0);
    obf::owned_vault<test_vault> owner(original);
    char* output = owner;
    CHECK(std::strcmp(output, "probe") == 0);
    auto copy = owner;
    owner.erase();
    for (size_t i = 0; i < 6; ++i) CHECK(output[i] == 0);
    CHECK(std::strcmp(static_cast<char*>(copy), "probe") == 0);
    CHECK(std::strcmp(static_cast<char*>(owner), "probe") == 0);
#endif
#if CONST_ENCRYPT_MODE == OBF_MODE_THREADLOCAL
    const char* first = tls_text();
    CHECK(std::strcmp(first, "TLS lifetime marker") == 0);
    CHECK(first == tls_text());
    // Proves the same site returns the decrypted cache rather than a fresh copy.
    const_cast<char*>(first)[0] = 'X';
    CHECK(tls_text()[0] == 'X');
    std::thread other([&] { CHECK(std::strcmp(tls_text(), "TLS lifetime marker") == 0); });
    other.join();
#endif

#if OBF_WINDOWS
    if (argc > 1) {
        using late = obf::import_slot<OBF_HASH_LOWER("obf_fixture.dll"), OBF_HASH("obf_fixture"), OBF_ELF_HASH("obf_fixture"), 0x4321>;
        CHECK(late::get("obf_fixture.dll", "obf_fixture") == nullptr);
        HMODULE module = LoadLibraryA(argv[1]);
        if (!module) std::printf("LoadLibraryA(%s) failed: %lu\n", argv[1], GetLastError());
        CHECK(module != nullptr);
        void* found = late::get("obf_fixture.dll", "obf_fixture");
        CHECK(found != nullptr);
        if (found) CHECK(reinterpret_cast<int(*)(int)>(found)(25) == 42);
        // Keep the DLL loaded while its pointer remains cached.
    }
    // An actual export can be located after the export directory in the image.
    alignas(16) unsigned char image[1024]{};
    image[0] = 'M'; image[1] = 'Z';
    *reinterpret_cast<int*>(image + 0x3c) = 0x80;
    image[0x80] = 'P'; image[0x81] = 'E';
    *reinterpret_cast<unsigned short*>(image + 0x98) = 0x20b;
    unsigned* dirs = reinterpret_cast<unsigned*>(image + 0x98 + 112);
    dirs[0] = 0x200; dirs[1] = 0x80;
    unsigned* exp = reinterpret_cast<unsigned*>(image + 0x200);
    exp[5] = 1; exp[6] = 1; exp[7] = 0x240; exp[8] = 0x244; exp[9] = 0x248;
    *reinterpret_cast<unsigned*>(image + 0x240) = 0x300;
    *reinterpret_cast<unsigned*>(image + 0x244) = 0x250;
    std::memcpy(image + 0x250, "Probe", 6);
    CHECK(obf::pe::find_export(image, OBF_HASH("Probe")) == image + 0x300);
    *reinterpret_cast<unsigned*>(image + 0x240) = 0x270;
    CHECK(obf::pe::find_export(image, OBF_HASH("Probe")) == nullptr);
    *reinterpret_cast<unsigned*>(image + 0x240) = 0;
    CHECK(obf::pe::find_export(image, OBF_HASH("Probe")) == nullptr);
    using pid_t = DWORD(WINAPI*)();
    using slot = obf::import_slot<OBF_HASH_LOWER("kernel32.dll"), OBF_HASH("GetCurrentProcessId"), OBF_ELF_HASH("GetCurrentProcessId"), 0x1234>;
    const char* module_hint = "kernel32.dll";
    const char* symbol_hint = "GetCurrentProcessId";
    CHECK(GET_EXPORT("kernel32.dll", "GetCurrentProcessId", pid_t) != nullptr);
    CHECK(GET_EXPORT("kernel32.dll", "Obfusheader_missing_export_42", pid_t) == nullptr);
    void* expected = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentProcessId"));
#elif OBF_LINUX
    using pid_t = int(*)();
    using slot = obf::import_slot<OBF_HASH("libc.so.6"), OBF_HASH("getpid"), OBF_ELF_HASH("getpid"), 0x1234, obf::hash_gnu("getpid")>;
    const char* module_hint = "libc.so.6";
    const char* symbol_hint = "getpid";
    CHECK(GET_EXPORT("libc.so.6", "getpid", pid_t) != nullptr);
    CHECK(GET_EXPORT("libc.so.6", "Obfusheader_missing_export_42", pid_t) == nullptr);
    void* expected = dlsym(RTLD_DEFAULT, "getpid");
    CHECK(obf::elf::resolve(OBF_HASH("libc.so.6"), OBF_HASH("getpid"), OBF_ELF_HASH("getpid"), obf::hash_gnu("getpid")) == expected);
    CHECK(obf::elf::resolve(OBF_HASH("libc.so.6"), OBF_HASH("getpid"), OBF_ELF_HASH("getpid")) == expected);
#endif
#if OBF_WINDOWS || OBF_LINUX
    std::atomic<int> errors{0};
    std::vector<std::thread> workers;
    for (int t = 0; t < 8; ++t) workers.emplace_back([&] {
        for (int i = 0; i < 1000; ++i) {
            void* p = slot::get(module_hint, symbol_hint);
            if (p != expected || !p || reinterpret_cast<pid_t>(p)() == 0) ++errors;
            if (concurrent_hidden_call(i) != i + 17) ++errors;
        }
    });
    for (auto& worker : workers) worker.join();
    CHECK(errors == 0);
    using missing = obf::import_slot<0, OBF_HASH("Obfusheader_missing_export_42"), OBF_ELF_HASH("Obfusheader_missing_export_42"), 0x5678>;
    CHECK(missing::get("kernel32.dll", "Obfusheader_missing_export_42") == nullptr);
#if IMPORT_CACHE
    CHECK(missing::masked_.load() == 0);
#endif
#endif
    std::printf("hardening failures=%d\n", failures);
    return failures != 0;
}
