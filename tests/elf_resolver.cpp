#include <cstdio>
#include <dlfcn.h>
#define CFLOW_BRANCHING 0
#include "../include/obfusheader.h"

int main(int argc, char** argv) {
    if (argc != 3) return 1;
    const unsigned modules[] = { OBF_HASH("libobf-gnu.so"), OBF_HASH("libobf-sysv.so") };
    for (int i = 0; i < 2; ++i) {
        void* handle = dlopen(argv[i + 1], RTLD_NOW | RTLD_LOCAL);
        if (!handle) { std::puts(dlerror()); return 2; }
        void* expected = dlsym(handle, "obf_fixture");
        void* actual = obf::elf::resolve(modules[i], OBF_HASH("obf_fixture"), OBF_ELF_HASH("obf_fixture"), obf::hash_gnu("obf_fixture"));
        if (!actual || actual != expected || reinterpret_cast<int(*)(int)>(actual)(25) != 42) return 3;
        if (obf::elf::resolve(modules[i], OBF_HASH("absent"), OBF_ELF_HASH("absent"), obf::hash_gnu("absent"))) return 4;
        void* via_slot = i == 0
            ? obf::import_slot<OBF_HASH("libobf-gnu.so"), OBF_HASH("obf_fixture"), OBF_ELF_HASH("obf_fixture"), 0x12u, obf::hash_gnu("obf_fixture")>::get(argv[i + 1], "obf_fixture")
            : obf::import_slot<OBF_HASH("libobf-sysv.so"), OBF_HASH("obf_fixture"), OBF_ELF_HASH("obf_fixture"), 0x34u, obf::hash_gnu("obf_fixture")>::get(argv[i + 1], "obf_fixture");
        if (via_slot != expected) return 5;
        dlclose(handle);
    }
    using missing_module = obf::import_slot<OBF_HASH("libobf-absent.so"), OBF_HASH("getpid"), OBF_ELF_HASH("getpid"), 0x56u, obf::hash_gnu("getpid")>;
    if (missing_module::get("libobf-absent.so", "getpid")) return 6;
    std::puts("GNU and SYSV resolver fixtures PASS");
}
