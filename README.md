# Obfusheader.h

<img src="https://i.ibb.co/sQQDTjn/preview.png"></img>

Obfusheader.h is a portable header file for C++14 and higher which implements multiple features for compile-time obfuscation such example string & decimal encryption, control flow, call hiding. It has no external dependencies, works on both windows and unix platforms, supports g++, gcc and visual c++ compilers. Obfusheader.h is intended to be the most easy way to provide a basic protection for sensitive data in your binaries. It's also designed to work with any g++ arguments which affect the compilation (-O3, Os, -fPIC, etc).

## Project goals

Unlike Windows x86_64 with VMProtect, Themida and other tools, on some platforms there's no good ways to protect your binaries, for example Arm64 / Arm32 android or linux ones. Because of that developing native ARM software (for example gaming mods) becomes a big problem - your product can be easily cracked by anyone. This gave me inspiration to create a handmade compile-time obfuscation using C++ macros, templates and constant expressions to provide basic protection measures for any platform, including android and Arm linux.

## Current features
- Support gcc, g++, clang, visual c++. C++14 and higher
- Works with any compiler flags (-Os, O3, O2), 100% safe
- Constant encryption (strings, any xor-able decimal types)
- 2 encryption modes (with thread-local storage and without)
- Basic inline ControlFlow (messes up with IDA / GHIDRA decompilers)
- Call hiding for both windows & linux (dlsym & GetModuleHandle)
- Dynamic key generation in compile-time (\_\_TIME\_\_ and \_\_COUNTER\_\_)

## Usage

### Settings
You can change them in the start of the header. This will affect how to obfuscation works in different ways. The default settings are the best so you won't need to change anything for it to work unless it's a special case. Note that disabling THREADLOCAL mode will expose your constant while compiling with optimization flags such as -O3, O2 so don't disable it if you use them.
```c++
// Settings 
#define THREADLOCAL
#define CFLOW
#define FORCEINLINE
```
### Basic constants encryption.
You can encrypt strings and any xor-able decimals easily. The macro is universal - it accepts any supported type as an argument.
```c++
#include <stdio.h>
#include "obfusheader.h"

int main() {
	printf(OBF("%s, %d, %c"), OBF("TEST"), OBF(123), OBF('c'));
    return 0;
}
```

Without optimization flags (regular G++):
<div align=center>
<img width="100%" src="https://i.ibb.co/cg1GR7P/image.png"><br/>
</div>
<br/>

With -O3 (agressive compiler optimizations):
<div align=center>
<img width="100%" src="https://i.ibb.co/MgJVkdM/image.png"><br/>
</div>
<br/>

### Hiding calls
You can hide any calls exported from external libraries on both linux and windows.

Windows call hiding example:
```c++
#include <stdio.h>
#include "obfusheader.h"

int main() {
    HANDLE stdOut = OBFUSCALL("kernel32.dll", "GetStdHandle", HANDLE(*)(DWORD))(STD_OUTPUT_HANDLE);
    if (stdOut != NULL && stdOut != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        const char * message = OBF("Hello, world!");
        OBFUSCALL("kernel32.dll", "WriteConsoleA", HANDLE(*)(HANDLE, const char*, DWORD, LPDWORD, LPVOID))
                 (stdOut, message, strlen(message), &written, NULL);
        getchar();
        return 0;
    }
} 
```


Linux call hiding example:

```c++
#include <stdio.h>
#include "obfusheader.h"

int main() {
   OBFUSCALL("printf", int(*)(const char*...))(OBF("There's no call here %d%% for sure"), OBF(100));
   return 0;
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
