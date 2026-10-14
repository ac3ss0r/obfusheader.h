# Obfusheader.h
<div align=center style="background-color: transparent;">
    <img src="images/obfusheader_preview_small.png"></img>
</div>

Obfusheader.h is a header-only library for C++14 and above, offering compile-time obfuscation through metaprogramming: string & decimal encryption, control-flow mutation, call hiding and import hiding. It is compatible with Windows and Linux, and supports g++, clang and Visual C++ on x86, x64, ARM64 and ARM32. Payloads are encoded at compile time and decoded at runtime, without a separate build tool. This raises the cost of static inspection; it is not cryptographic protection against someone who can run or modify the program.

The header is organised into 15 numbered sections, one per protection, so each part can be read, ported or switched off on its own.

## 🛠️ Current features

<div align=center style="background-color: transparent;">
    <img src="images/before_after.png"></img>
    <text>Sample crackme with & without obfusheader.h</text>
</div>

### Obfuscation features
- Fully compile-time constant encryption (strings, chars, integers and **bools**) with two modes - `NORMAL` & `THREADLOCAL` - and a per-site key generated at compile time
- Hidden references to the encrypted data: each payload sits in a table of same-sized decoy rows, reached through an obfuscated index, exactly like the hidden call tables
- Payload integrity check: the compiler records a checksum of the original payload and the decryptor re-verifies it; a mismatch returns a zeroed buffer
- Call hiding with decoy stubs, per-slot pointer masks, and thread-safe first-use initialization
- Manual import hiding: PEB walking on Windows, ELF dynamic/link-map and symbol-hash-table parsing on Linux, with API names resolved as compile-time hashes
- `if`/`else`/`for`/`while`/`switch`/`return` control-flow mutation with opaque predicates, plus a mode that keeps all of it legal inside `constexpr` code
- Polymorphic inline asm engine: 12 executed and 6 unreachable trap blocks per architecture, combined randomly per expansion site
- Compile-time variation from the build seed, \_\_LINE\_\_ and \_\_COUNTER\_\_, with avalanche mixing forced into constant evaluation; derived constants are emitted with the decoder
- Watermarking - messages left in the binary that survive any optimization and show up in decompilers
- Fake signatures to trick DIE (Detect-It-Easy) and other detectors into reporting VMProtect, Themida, Denuvo & friends

### Additional modules
- Inline implementations of common C string routines (`strcpy`, `strlen`, `strncat`, `strcmp`, `strncmp`, `strstr`, `strtoul`); inspect optimized imports if avoiding libc calls matters

## 📑 Usage

Add the include directory to your project and include the header:

```c++
#include "obfusheader.h"
```

⚠️ **Include it last.** Section 15 redefines the keywords `if`, `else`, `for`, `while`, `switch` and `return`, and a macro affects every line that comes after it - including any standard library or third-party header you include afterwards. Put obfusheader.h below your other includes, or set `CFLOW_BRANCHING 0`.

`if constexpr (...)` is never mutated: the macro is function-like, so it only fires when `(` directly follows `if`.

### Settings

Every option is guarded with `#ifndef`, so you never have to edit the file - set it before the include, or per translation unit on the command line:

```c++
#define CFLOW_BRANCHING 0        // this file is full of constexpr code
#include "obfusheader.h"
```

```
g++ -O2 -DCFLOW_ASM_JUNK=0 -DVAULT_SLOTS=6 main.cpp
```

The defaults, in the order they appear in section 1:

| Option | Default | Meaning |
|---|---|---|
| `CONST_ENCRYPTION` | `1` | Encrypt literals passed to `OBF()` / `MAKEOBF()` |
| `CONST_CLEAR` | `1` | Clear runtime owners' typed plaintext buffers on destruction; `0` disables automatic clearing |
| `OBF_SEED` | Seconds encoded from `__TIME__` | Set the same unsigned seed in every translation unit; vary it between builds for diversity, or fix it for reproducibility |
| `CONST_ENCRYPT_MODE` | `OBF_MODE_NORMAL` | `OBF_MODE_NORMAL` or `OBF_MODE_THREADLOCAL` (`NORMAL` / `THREADLOCAL` still accepted) |
| `VAULT_SLOTS` | `4` | Decoy rows stored next to each payload (1-8) |
| `VAULT_CHECK` | `1` | Verify the decrypted payload against a compile-time checksum |
| `CFLOW_BRANCHING` | `1` | Master switch for the keyword mutation |
| `CFLOW_CONST_DECRYPTION` | `1` | Fake branches inside the string/decimal decryptor |
| `CFLOW_ASM_JUNK` | `1` | `0` removes all inline asm from control flow, making it legal inside `constexpr` |
| `CFLOW_IF` / `CFLOW_ELSE` / `CFLOW_FOR` / `CFLOW_WHILE` / `CFLOW_SWITCH` / `CFLOW_RETURN` | = `CFLOW_BRANCHING` | Leave individual keywords alone |
| `INDIRECT_BRANCHING` | `1` | Opaque conditional jumps inside the runtime gate |
| `JUNK_ASM` | `1` | Emit polymorphic asm blocks (`ASM_JUNK`, `STACKBRK`) |
| `JUNK_TRAP` | `1` | Emit unreachable `int3` / `ud2` / `brk` / `bkpt` bait |
| `CALL_SLOTS` | `10` | Entries in a hidden call table (2-10) |
| `IMPORT_RESOLVER` | `OBF_RESOLVER_AUTO` | `OBF_RESOLVER_AUTO` / `_MANUAL` / `_API` |
| `IMPORT_CACHE` | `1` | Cache resolved imports XOR-masked in `.data` |
| `FAKE_SIGNATURES` | `0` | Protector bait sections (section 13) |
| `INLINE_STD` | `1` | The inline string routines (section 14) |
| `KERNEL_MODE` | `0` | Never pull in `<windows.h>` / `<dlfcn.h>` |
| `WATERMARKING` | `1` | Enable the `WATERMARK()` machinery |

Bad combinations are caught at compile time with a pointed `#error` instead of failing much later inside a template.

### Compile-time constant encryption

You can encrypt strings, chars and any integer type. The macro is universal - it deduces the element type and length from the argument.

```c++
printf("char*: %s\n"
       "int (dec): %d\n"
       "long long: %lld\n"
       "int (hex): 0x%x\n"
       "boolean: %d\n",
       OBF("test"), OBF(123),
       OBF(9223372036854775807LL),
       OBF(0x123), OBF(true));
```

The original values are restored at runtime. The test matrix scans dedicated binaries for plaintext markers, including optimized and LTO builds; this is evidence for those builds, not a guarantee for every compiler or use site. Only compile-time constants can be encrypted - a literal, or a `constexpr` object with static storage.

Bools are encrypted correctly on their own. The previous release needed `#define true 1` / `#define false 0` for this, because the payload was stored in a `bool` and lost every key bit but the last while the decryptor tested for non-zero; `OBF(true)` silently came back as `false`. The payload is now stored in an unsigned integer of the same width as its type; `true` and `false` are never redefined.

Three layers make each string hard to find:

- The bytes are cipher text, produced by a hash of `(key, index)` rather than `key + index`, so a long string does not walk into the next key byte.
- Each site selects one of eight reversible instruction families: XOR, addition/XOR, rotation/addition/XOR, multiplication/XOR, multiplication/rotation/addition/XOR, two different three-round Feistel networks, or keyed addition/rotation/XOR. Multipliers, inverse multipliers, rotations and round constants vary per site; four key-schedule shapes are selected by the full 32-bit site key. These are obfuscation transforms, not reviewed cryptographic ciphers.
- The payload lives in a table of `VAULT_SLOTS` same-sized rows where only one is real, and the row is selected through a masked index recovered by a call that cannot be inlined. Neither the instruction nor the static layout points at the string.

Each row also uses a site-specific permutation of element positions. The decoder reconstructs logical order into a typed output buffer and re-encodes the working row, so contiguous ciphertext positions do not imply contiguous plaintext positions.

⚠️ Payload buffers use stack or thread storage. With `CONST_CLEAR=1`, runtime owners clear their plaintext buffer through volatile stores when destroyed. TLS destructor registration and first-use guards can add platform-dependent C++ runtime work, including allocations by the runtime. Decryption in `NORMAL` happens in the caller's own frame, so the pointer is only valid while the owner is alive:

```c++
// Not safe: the row belongs to a temporary that dies with the statement
const char* str = OBF("test");
printf("1: %s\n", str);

// Safe: the pointer is used inside the same full-expression
printf("2: %s\n", OBF("test"));

// Safe: MAKEOBF keeps the encrypted object alive, and it decrypts itself on first use
auto obf = MAKEOBF("test");
printf("3: %s\n", (char*)obf);
printf("4: %s\n", (char*)obf);   // still correct, it will not decrypt twice
```

With `CONST_ENCRYPT_MODE` set to `THREADLOCAL`, `OBF()` decrypts the cached object once per thread and returns its buffer. The pointer remains valid until thread exit; later calls at the same expansion site reuse the buffer, including any modifications. `auto obj = MAKEOBF(...)` still makes an owned copy; use `auto&` to refer to the thread cache. This mode intentionally retains plaintext longer than `NORMAL`.

`VAULT_CHECK` stores a checksum taken from the plaintext. On a mismatch the selected row is zeroed, including its terminator, and later conversions keep returning that zeroed result. This detects accidental or unsophisticated payload changes; an attacker can patch the check or forge its checksum. Set it to `0` to remove the extra pass.

<div align=center>
    <img width="100%" src="images/const_encryption.png"><br/>
    <text>The logic isn't affected - the data is decrypted in runtime</text>
</div>

<br/>

### Control flow mutation

With `CFLOW_BRANCHING` on, the keywords are rewritten through opaque predicates built on a volatile constant pool, so the loads cannot be folded and the fake branches survive into the release build:

```c++
if (inline_strcmp(password, correct) == 0) {   // mutated, still one branch
    ...
}
```

Each mutation preserves behaviour: the guard loop runs exactly once, `return` keeps returning on every path, and `else` rebinds to a branch that can never be taken. Conditions containing commas (`if (a, b)`) keep working.

Comma operands retain their sequencing. `switch` retains the native condition type, including large unsigned values and scoped enums; contextual conversions of class objects are evaluated once without copying the object. Fake `else` paths terminate in a never-returning decoy, keeping two-return branches and `if constexpr` functions valid under return-path diagnostics.

In runtime mode each site also gets a gate selected from the reversible instruction families, with its own constants and volatile intermediate storage. Vault and hidden-call gates are keyed by the payload/call site seed. This adds code size and runtime work; disabling `CFLOW_ASM_JUNK` selects the simpler constexpr-compatible path.

The mutation is per keyword, so a file that cannot take one can opt out of just that keyword:

```c++
#define CFLOW_SWITCH 0    // a big switch-based state machine
#include "obfusheader.h"
```

### Constexpr / compile-time code

Inline asm, volatile reads and non-`constexpr` calls are not allowed inside a constant expression, so the mutated keywords used to break every `constexpr` function and `static_assert` in a project. `CFLOW_ASM_JUNK 0` fixes that: the same opaque predicates are rebuilt on a `constexpr` gate that reads nothing volatile and contains no asm.

```c++
#define CFLOW_ASM_JUNK 0
#include "obfusheader.h"

constexpr int sum(int n) {
    int total = 0;
    for (int i = 1; i <= n; ++i) {   // mutated, still constant-evaluable
        if (i % 2 == 0) total += i;
        else            total += 1;
    }
    return total;
}
static_assert(sum(6) == 15, "");
```

The gate stays `__declspec(noinline)` / `__attribute__((noinline))`, but that alone does not prevent interprocedural constant propagation. The constexpr mode favors compatibility and can lose flow obfuscation under optimization. `return` is left alone before C++20, and never-taken decoy blocks can be folded away. Ciphertext is read through a volatile lvalue independently of this mode to resist compile-time recovery of plaintext.

### Call hiding

Internal calls use a table whose slot selection and masks are chosen at compile time. Every entry is XOR-masked with its own pointer-width mask and read through a volatile lvalue; the selected pointer is restored at runtime. Unused slots hold masked decoy stubs and impossible addresses. Thread-safe local static initialization supports calls before `main` and concurrent first use; keep the compiler's thread-safe-static support enabled when those calls can run concurrently. Target addresses remain recoverable from initialization code and relocations.

```c++
CALL(&printf, "Very secure call\n");
HIDE_PTR(&some_function)(args);
```

<div align=center>
    <img width="100%" src="images/call_hide.jpg"><br/>
    <text>Call hiding demo</text>
</div>
<br/>

### Import hiding

External APIs are resolved by reading the loader's own data structures instead of asking for them, so the call leaves nothing in the import table:

- **Windows** - `TEB` -> `PEB` -> `Ldr->InMemoryOrderModuleList`, then the PE export directory of the matching module.
- **Linux** - the image's `DT_DEBUG` -> the linker's `r_debug` -> the link map chain, then each object's GNU or SYSV symbol hash table.

Names are matched as compile-time hashes mixed with a per-build salt, while API fallback hints are encoded like other literals. The resolved pointer is cached XOR-masked with a pointer-width mask. Cache loads and stores are atomic; failed resolutions are retried. Hashes and masks remain recoverable from the program.

```c++
typedef HMODULE(WINAPI* load_lib_t)(LPCSTR);
typedef int (WINAPI* msg_box_t)(HWND, LPCSTR, LPCSTR, UINT);

CALL_EXPORT("kernel32.dll", "LoadLibraryA", load_lib_t, "user32.dll");
CALL_EXPORT("user32.dll",  "MessageBoxA",  msg_box_t, NULL, "Real", "Msgbox", MB_OK);
```

The signature is the same on both systems now - `(module, symbol, prototype, args...)`. On Linux the module is matched against the object's file name, so pass `"libc.so.6"`, `"libm.so.6"`, and so on.

⚠️ Two things about that third argument. It must describe the API as it really is: on 32-bit Windows the Win32 functions are `WINAPI` (`__stdcall`), and calling one through a plain cdecl pointer leaves the stack wrong - on x64 there is a single convention so this cannot happen. And name the type through a `typedef` (or `using`): `CALL_EXPORT(..., HMODULE(WINAPI*)(LPCSTR), ...)` looks equivalent, but the macro expands its prototype into a cast and MSVC reads `HMODULE(...)` there as a functional cast instead of a type (error C2143), while clang accepts it.

`IMPORT_RESOLVER` selects the backend: `OBF_RESOLVER_AUTO` (default) tries the manual walk and falls back to `GetProcAddress` / `dlsym`, `OBF_RESOLVER_MANUAL` never references those APIs at all, `OBF_RESOLVER_API` keeps the old behaviour. If nothing can resolve the name you get a null pointer back rather than a random address.

Use `GET_EXPORT(module, symbol, prototype)` when an export may be absent. It returns the typed pointer without calling it, so the caller can check for null. `CALL_EXPORT` is the direct-call shorthand and assumes resolution succeeds:

```c++
auto load = GET_EXPORT("kernel32.dll", "LoadLibraryA", load_lib_t);
if (load) load("user32.dll");
```

The Linux walk follows the glibc link map layout (bionic matches it). Other libc layouts are rejected by the sanity checks and fall back to `dlsym`, so they resolve correctly but are not hidden.

<br/>
    <div align=center>
        <img width="100%" src="images/export_hiding.png"><br/>
        <text>Import hiding demo</text>
    </div>
<br/>

### Assembly junk

Two macros can be dropped into any function. Each expansion draws four independent random numbers, so the emitted blocks and their order differ per site - about 12^4 shapes:

- `ASM_JUNK` - executed instructions. Every one is a no-op or works on a scratch register the compiler owns, so program state never changes.
- `STACKBRK` - the same plus trap encodings (`int3`, `ud2`, `brk`, `bkpt`) parked inside a branch the volatile predicate never takes, giving a disassembler breakpoints that are never reached.

The blocks are defined per target: GNU asm for x86, x64, ARM64 and ARM32; byte-emitting `__asm` for MSVC x86; `__nop()` / `_mm_pause()` / `__debugbreak()` for MSVC x64, which has no inline asm. On any unsupported combination the macros expand to nothing.

`INDIRECT_BRANCH` is the separate trick that breaks IDA's decompiler: an opaque conditional jump over a byte that disassembles as the start of an instruction.

### Binary watermarking

Leave messages and ASCII art in your binary that do not affect execution but appear in IDA/GHIDRA. Use the **WATERMARK** macro; inspired by <a href="https://github.com/xoreaxeaxeax/REpsych">REpsych</a> and some java obfuscators which also do that.

```c++
WATERMARK("                                                           ",
          "                   00                 00                   ",
          "                   00000           0000                    ",
          "                  0    000      0000    0                  ",
          "                000       000 0000       0 0               ",
          "              00  0000    000000      000  00              ",
          "             0000000 000  0 000 0   00 00 0 00             ",
          "            0 0 0 0 0 00  00000000   000 000000            ",
          "           0 0 0 0 0     00  00 00  0 00 0 0 0 0           ",
          "          0 0 0 0 0 0 00 000   0 000  0 0       0          ",
          "          0 0 0 0  0 0  0 00000 000  0 0 0 0 0000          ",
          "         0 0   0        0 0 000 0 0            0 0         ",
          "        0 0 0           0 0000000 0             0 0        ",
          "       0              00000000 000000            0 0       ",
          "                      0 00000000000 0     00               ",
          "                0    0    0 000 0    0  0 0                ",
          "                          00000000                         ",
          "                         000000000                         ",
          "                         000000000                         ",
          "                           000                             ",
          "                                                           ");
```

The strings are pushed through a volatile function pointer that is initialised to a real function, so they survive optimization and land in the decompiler's cross-reference window as a plausible drawing routine.

<div align=center>
    <img width="100%" src="images/watermark.png"><br/>
    <text>Watermarking in different RE tools</text>
</div>
<br/>

### Fake signatures

A windows-only feature that adds sections Detect-It-Easy, PeExeInfo and Nauz File Detector attribute to commercial protectors, making a reverse-engineer doubt the binary is worth the time.

```c++
#define FAKE_SIGNATURES 1
```

<div align=center>
    <img width="100%" src="images/die-preview.png"><br/>
    <text>Detect-It-Easy output</text>
</div>
<br/>

⚠️ If you're using Visual C++ be sure to disable whole program optimization in the project properties. Otherwise the compiler won't create additional sections in the binary.
<div align=center>
    <img width="100%" src="images/vsc-settings.jpg"><br/>
</div>
<br/>

### Additional features & modules

**RND(min, max)** generates a compile-time random number. Every expansion draws its own value from \_\_COUNTER\_\_, \_\_LINE\_\_ and \_\_TIME\_\_ after an avalanche mix.

```c++
printf("Some random value: %d\n", RND(0, 10));
```

**INLINE** and **NOINLINE** force or forbid inlining on any compiler. **SECTION(name)** places a variable in a custom section. **CAST(T, v)**, **RCAST(T, v)** and **CCAST(T, v)** are the portable spellings of the named casts, and work in C too.

**OBF_HASH(name)**, **OBF_HASH_LOWER(name)** and **OBF_ELF_HASH(name)** compute a name's hash at compile time; `OBF_HASH` is salted per build, `OBF_ELF_HASH` is the plain ELF hash the loader's own tables use.

**BLOCK_TRUE(...)** / **BLOCK_FALSE(...)** wrap a statement in an opaque always-taken / never-taken branch. **SEGFAULT** is a deliberate hard fault for a path that must never be reached.

Also obfusheader reimplements the most common C string methods fully inlined: **strcpy, strlen, strncat, strcmp, strncmp, strstr, strtoul**. Use them to avoid hookable imports.

```c++
if (inline_strcmp(password, correctPassword) == OBF(0)) {
    printf(OBF("Congratulations! You have successfully cracked the program. \n"));
} else {
    printf(OBF("Sorry, the password is incorrect. Try again!\n"));
}
```

## 🧪 Testing

Automated behavioral, concurrency, resolver and plaintext-leak tests live in `tests/`. Build outputs should go outside the checkout:

```powershell
./tests/run_tests.ps1 -GccRoot C:/toolchains/gcc64 -Clang C:/toolchains/LLVM/bin/clang++.exe
```

The test runners require Node.js without additional packages. The Windows GCC/Clang runner uses the tested w64devkit/MinGW layout, writes all artifacts to `%TEMP%`, and scans narrow and wide markers. It covers `-O0`, `-O2`, `-O3`, `-Os`, LTO, minimal protection, constexpr flow, TLS, manual/API imports, disabled caching/clearing, minimum table sizes and C++17/20. GCC builds without LTO support explicitly skip that configuration; Clang still tests it. Other MinGW distributions may need adjusted Clang link flags.

```powershell
./tests/run_msvc_tests.ps1 -VcVarsAll 'C:/Program Files/Microsoft Visual Studio/18/Insiders/VC/Auxiliary/Build/vcvarsall.bat'
```

The MSVC runner initializes both x64 and x86 environments, checks `/Od`, `/O2`, `/GL` + LTCG and the feature modes, and keeps EXE, OBJ, PDB and linker outputs in `%TEMP%`. C fallback is tested separately. Executable tests have a 30-second timeout and bounded output.

```sh
bash tests/run_tests.sh /tmp/obfusheader-tests
```

The Linux runner uses `$CXX` (default `g++`), tests LTO and both real GNU/SYSV shared-library fixtures. `hardening.cpp` additionally checks concurrent resolution, failed lookups, tampered payloads, and per-thread buffer reuse. On Windows it verifies that a lookup missed before loading a DLL succeeds afterward.

For an optimized polymorphism binary, compare actual opcode sequences rather than source expressions:

```sh
node tests/audit_polymorphism.mjs objdump /tmp/obfusheader-tests/default-polymorphism
```

The audit ignores addresses, operands and alignment padding. All eight decoder families retain distinct opcode sequences under the tested GCC and Clang optimizations. That is a measurable diversity check, not a measure of cryptographic strength.

```
g++ -std=c++14 -O2 -I../include selftest.cpp    -o selftest.exe && selftest.exe
cl    /std:c++14 /O2 /I../include selftest.cpp /Fe:selftest.exe && selftest.exe
```

- **`selftest.cpp`** - asserts on behavior, including all supported payload types, hidden calls, import resolution, and mutated keywords with counted side effects. It also covers comma sequencing and 64-bit switch values on 32-bit targets.
- **`leak_probe.cpp`** - literals used *only* inside `OBF()`, for scanning the produced binary for plaintext. The self-test cannot serve this purpose because a failed assertion prints the condition it tested.
- **`c_fallback.c`** - the C path, where `OBF()` is identity but the control flow mutation and string routines still apply.
- **`cpp_tests.cpp`** - the original interactive crackme demo.

`polymorphism.cpp` checks all byte values against all byte keys, all 16-bit values, and sampled 32/64-bit values for every family (2,883,584 roundtrips per run), plus layout permutations. `asm_regression.cpp` exercises every executed junk block with live registers, comparison results and stack locals. The current changes are validated on Windows with GCC 16.2, Clang 22.1 and MSVC x64/x86, and on x86-64 Linux with GCC 13.3. ARM needs separate runtime validation.

## ⚠️ Known limitations

- Floating point literals cannot be encrypted. Reaching a `float`'s bit pattern at compile time needs `std::bit_cast`, i.e. C++20; the header rejects the attempt with a `static_assert` naming that reason rather than quietly producing a wrong value.
- The runtime decryptors are not `constexpr`, so `OBF()` works at runtime only, and only on literals.
- Plaintext lives in a typed output row after decoding. The unsigned working row is re-encoded, avoiding a second retained plaintext copy and aliasing through a mismatched pointer type. This adds one row of storage and an encoding pass. Automatic clearing covers owned buffers on destruction, not registers, compiler spills, caller-made copies or abrupt termination. `THREADLOCAL` retains its output until thread exit. Keys, masks, checksums, tables and decoder code ship with the application. This is not a safe place to store credentials or long-term secrets.
- Build-time randomness is deterministic and predictable. The default timestamp repeats daily. Set `OBF_SEED` and configuration macros consistently across all translation units; a seed is for variation, not secrecy. A wide key does not create entropy absent from the seed and source location.
- Salted 32-bit module/name hashes can collide. They are lookup shortcuts, not authentication of loaded code.
- Algebraic identities, junk instructions, fake branches and signatures can be recognized or removed. Non-inlining and volatile accesses impede compiler simplification, not symbolic analysis or emulation. Hidden-call targets remain visible in relocations and at runtime.
- A checksum is not authentication. Failure produces zeros, which callers must handle; the scalar API has no separate error channel. Fake protector signatures and watermarks are intentional fingerprints rather than protection against a determined analyst.
- Manual resolvers trust loader-owned images, not arbitrary malformed PE/ELF buffers. Windows forwarded exports require the API fallback; manual-only mode can return null. Linux symbol versions, TLS exports and non-glibc loader layouts are not fully modeled. The Linux API fallback uses the requested loaded module (`RTLD_NOLOAD`), including its dependency scope; zero module hash selects the global scope. Check the result of a resolver before calling it; `CALL_EXPORT` directly calls the returned pointer.
- Import caching assumes resolved modules remain loaded. Unloading a module can leave a stale pointer. The atomic cache supports concurrent lookups but does not synchronize concurrent module unloading or changes to the loader's lists. Disabling caching removes retained pointers, not loader-list races.
- Inline C routines can still become compiler-generated libc calls. They are not a guaranteed defense against hooks; inspect release imports and use compiler options appropriate to your build.
- Section 15's keyword mutation is global and textual: it applies to anything after the include. Turn it off per file, or per keyword, when a third-party header cannot take it.
- Declaration conditions (`if (int x = ...)`, C++17 init-statements) are not supported by the expression macros; disable the corresponding keyword mutation in those files. Sharing a mutable `MAKEOBF` object across threads requires caller synchronization.
- Strip release symbols and keep debug/PDB files separate: template names and debug metadata can expose implementation details and site constants. Expanded per-site gates, masks and layouts increase code size and runtime work; benchmark your actual application. MSVC's constexpr-safe mode leaves `return` untouched even in C++20 to avoid its evaluator's label-wrapper limitation.

## ⭐ Credits

Special thanks to these people: <a href="https://github.com/dosx-dev">DosX-dev</a>, <a href="https://github.com/ARandomPerson7">RandomPerson7</a> for suggestions & great ideas! Your help is greatly appreciated
