# Obfusheader.h
<div align=center style="background-color: transparent;">
<img src="https://i.ibb.co/sQQDTjn/preview.png"></img>
</div>

Obfusheader.h is a portable header file for C++14 and higher which implements multiple features for compile-time obfuscation for example string & decimal encryption, control flow, call hiding. It has no external dependencies, works on both windows and unix platforms, supports g++, gcc and visual c++ compilers. Obfusheader.h is intended to be the most easy way to provide a basic protection for sensitive data in your binaries. It's also designed to work with any g++ arguments which affect the compilation (-O3, Os, -fPIC, etc).

## Project goals

Unlike Windows x86_64 with VMProtect, Themida and other tools, on some platforms there's no good ways to protect your binaries, for example Arm64 / Arm32 android or linux ones. Because of that developing native ARM software (for example gaming mods) becomes a big problem - your product can be easily cracked by anyone. This gave me inspiration to create a handmade compile-time obfuscation using C++ macros, templates and constant expressions to provide basic protection measures for any platform, including android and Arm linux.

## Current features
- Support gcc, g++, clang, visual c++. C++14 and higher
- Works with any compiler flags (-Os, O3, O2), 100% safe
- Constant encryption (strings, any xor-able decimal types)
- 2 encryption modes (with thread-local storage and without)
- Basic inline ControlFlow (messes up with IDA / GHIDRA decompilers)
- Import hiding for both windows & linux (dlsym & GetModuleHandle)
- Dynamic key generation in compile-time (\_\_TIME\_\_ and \_\_COUNTER\_\_)
- Indirect branching (call hiding) using static & dynamic storagers
- Binary watermarking for IDA/GHIDRA decompilers

## Usage

### Settings
You can change them in the start of the header. This will affect how to obfuscation works in different ways. The default settings are the best so you won't need to change anything for it to work unless it's a special case. Note that disabling **THREAD_LOCAL** mode will expose your constant while compiling with optimization flags such as -O3, O2 so don't disable it if you use them. You can disable **CFLOW** (control flow) if you prefer optimization over security. You can also disable **FORCE_INLINE** which is not recommended.

```c++
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
```

### Basic constants encryption.
You can encrypt strings and any xor-able decimals easily. The macro is universal - it accepts any supported type as an argument.
```c++
// Constant encryption
printf("char*: %s\n" 
       "int: %d\n"
       "long long: %llu\n" 
       "hexval: 0x%x\n",
       OBF("test"), OBF(123),
       OBF(9223372036854775807),
       OBF(0x123));
```
The logic of the program will not be affected.
<div align=center>
<img width="100%" src="https://github.com/ac3ss0r/obfusheader.h/blob/main/images/const_encryption_output.png?raw=true"><br/>
</div>
And this is how it looks in IDA decompiler.
<div align=center>
<img width="100%" src="https://github.com/ac3ss0r/obfusheader.h/blob/main/images/const_encryption_ida.png?raw=true"><br/>
</div>
<br/>

### Binary watermarking
You can leave messages and ASCII arts in your binary which will not affect execution, but will be displayed in IDA/GHIDRA decompilers. To do that use the **WATERMARK** macro. This doesn't affect execution in any way - the feature is purely visual, just to mess with the crackers or leave some kind of message in the binary. It's made in special was so it won't be optimized away with any compiler flags/optimizations.

```c++
// Watermarking for IDA/Ghidra
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

This is how it looks in IDA decompiler (G++/CLANG).
<div align=center>
<img width="100%" src="https://github.com/ac3ss0r/obfusheader.h/blob/main/images/watermark_ida_a.png?raw=true"><br/>
</div>
<div align=center>
<img width="100%" src="https://github.com/ac3ss0r/obfusheader.h/blob/main/images/watermark_ida_b.png?raw=true"><br/>
</div>
Using Visual C++ it looks a little bit different.
<div align=center>
<img width="100%" src="https://github.com/ac3ss0r/obfusheader.h/blob/main/images/watermark_ida_c.png?raw=true"><br/>
</div>
<br/>

### Indirect branching (call hiding)
Obfusheader allows you to hide calls to any internal methods in the program. To do that you can use one of two existing macros - **STATIC_HIDE_CALL** and **DYNAMIC_HIDE_CALL**. The difference is that static call hiding stores pointer references directly in the .data section, and dynamic initialized them directly in runtime.

```c++
// Indirect branching (call hiding)
CALL(&printf, "Very secure default call\n");
STATIC_HIDE_CALL(&printf, "Very secure static call\n");
DYNAMIC_HIDE_CALL(&printf, "Very secure dynamic call\n");
```

This is how it looks in IDA.
<div align=center>
<img width="100%" src="https://github.com/ac3ss0r/obfusheader.h/blob/main/images/static_call_hider_ida.png?raw=true"><br/>
</div>
<div align=center>
<img width="100%" src="https://github.com/ac3ss0r/obfusheader.h/blob/main/images/dynamic_call_hider_ida.png?raw=true"><br/>
</div>
<br/>


### Import hiding
You can hide any calls exported from external libraries on both linux and windows.

Windows call hiding example:
```c++
 // Hiding import calls on windows
 HANDLE stdOut = CALL_EXPORT("kernel32.dll", "GetStdHandle", HANDLE(*)(DWORD))(STD_OUTPUT_HANDLE);
 if (stdOut != NULL && stdOut != INVALID_HANDLE_VALUE) {
     DWORD written = 0;
     const char* message = OBF("Very secure call\n");
     CALL_EXPORT("kernel32.dll", "WriteConsoleA", HANDLE(*)(HANDLE, const char*, DWORD, LPDWORD, LPVOID))
         (stdOut, message, strlen(message), &written, NULL);
}
```
<div align=center>
<img width="100%" src="https://github.com/ac3ss0r/obfusheader.h/blob/main/images/hide_imports.png?raw=true"/><br/>
</div>
<br/>
Linux call hiding example:

```c++
// Hiding import calls on unix
OBFUSCALL("printf", int(*)(const char*...))(OBF("Even more secure call"));
```

### Additional features

Obfusheader uses a few unique macroses which can be used in your programs. **RND(min, max)** can be used to generate decimals in compiletime. 
```c++
printf("Some random value: %d\n", RND(0, 10));
```
**INLINE** can be used to forcefully inline any method.
```c++
INLINE void do_something() {
	// the method will be fully inlined
}
```

## Existing solutions

There already are some similar solutions for compile-time obfuscation, but all of them have problems that forced me to implement my own. 

1. [Oxorany](https://github.com/llxiaoyuan/oxorany)

    Seems like a really good compile-time obfuscator, has an universal macro with input type detection and control flow implementation. But sadly is affected by optimization flags in general. 
    
Test C++ source:
<div align=center>
<img width="80%" src="https://i.ibb.co/sycTF5j/image.png"/><br/>
</div>
<br/>

Used compiler:
<div align=center>
<img width="80%" src="https://i.ibb.co/3N9RfsF/image.png"/><br/>
</div>
<br/>

The string remains in the binary (compiled without -O3):
<div align=center>
<img width="80%" src="https://i.ibb.co/SrnTtJ3/2023-11-20-062753.png"/><br/>
</div>
<br/>

When compiling with -O3 the string is encrypted, but the control flow gets eaten:
<div align=center>
<img width="80%" src="https://i.ibb.co/xhq5Fzh/image.png"/><br/>
</div>
<br/>

2. [skCrypter](https://github.com/skadro-official/skCrypter)

    Another one more old compile-time obfuscation header. Works pretty fine without any compiler flags, but the encryption gets completely simplified if optimization flag is added.

Test C++ program:
<div align=center>
<img width="80%" src="https://i.ibb.co/LhQqQT8/image.png"/><br/>
</div>
<br/>

Without -O3 arguments:
<div align=center>
<img width="80%" src="https://i.ibb.co/1rL29xf/image.png"/><br/>
</div>
<br/>

With optimizations:
<div align=center>
<img width="50%" src="https://i.ibb.co/T2L8CWr/image.png"/><br/>
</div>
<br/>
