/*
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <intrin.h>
#include <winternl.h>

#pragma warning(disable:4996) 

#ifdef _WIN64
    #define PEB_OFFSET 0x60
#else
    #define PEB_OFFSET 0x30
#endif

#if _WIN64
    #define GETTEB() (_TEB*)__readgsqword(0x30)
#else
    #define GETTEB() (_TEB*)__readfsdword(0x18)
#endif

void* GetProcAddress_Custom(const wchar_t* moduleName, const char* functionName) {
    _TEB* pTeb;
    _PEB* pPeb;
    pTeb = GETTEB();
    assert(pTeb != 0);
    pPeb = pTeb->ProcessEnvironmentBlock;
    assert(pPeb != 0);

    LIST_ENTRY* entry = pPeb->Ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY* start = &pPeb->Ldr->InMemoryOrderModuleList;

    while (entry != start) {
        PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        // Convert to lowercase
        wchar_t current_name[256] = L"";
        memcpy(current_name, tableEntry->FullDllName.Buffer, tableEntry->FullDllName.Length);
        _wcslwr(current_name);

        if (wcsstr(current_name, moduleName)) {
            printf("Found: %wZ\n", &tableEntry->FullDllName);
            PBYTE baseAddress = (PBYTE)tableEntry->DllBase;
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);
            if (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
                DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(baseAddress + exportDirRva);

                PDWORD functions = (PDWORD)(baseAddress + exportDir->AddressOfFunctions);
                PDWORD names = (PDWORD)(baseAddress + exportDir->AddressOfNames);
                PWORD ordinals = (PWORD)(baseAddress + exportDir->AddressOfNameOrdinals);

                for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
                    // Compare the function name
                    if (strcmp((char*)(baseAddress + names[i]), functionName) == 0) {
                        printf("Function: %s at 0x%X\n", baseAddress + names[i], functions[ordinals[i]]);
                        return (void*)(baseAddress + functions[ordinals[i]]);
                    }
                }
            }
        }

        entry = entry->Flink;
    }
    return NULL;
}

#define CALL(def, addr, ...) reinterpret_cast<def>(addr)(__VA_ARGS__);

int main() {
    LoadLibraryA("user32.dll"); // reimplement later
    void* pFunctionAddress = GetProcAddress_Custom(L"user32.dll", "MessageBoxA");
    assert(pFunctionAddress = (void*)&MessageBoxA);
    printf("%p %p", pFunctionAddress, &MessageBoxA);
    CALL(int(*)(int, const char*, const char*, int), pFunctionAddress, 0, "Hello, world", "Title", 0);
    return 0;
}*/

// Не знаю что смешнее: 

#include <stdio.h>
#include <string.h>
#include "../include/obfusheader.h"
   
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow) {
	_EXP_CFLOW(
        anti_analysis();
        anti_debug();
        anti_tamper();
    )
    _EXP_CFLOW();
    char buff[256];
    CALL(&printf, OBF("/ Obfusheader.h beta max preset crackme v1. (visit https://github.com/ac3ss0r/obfusheader.h for more info).\\\n"
        "- Compiler: Visual C/C++, x86 (32bit)                                                                      -\n"
        "- Author: Acessor (github.com/ac3ss0r)                                                                     -\n"
        "- Difficulty: Medium                                                                                       -\n"
        "\\ If you crack it DM me on telegram. @ac3ss0r. Good luck!                                                  /\n\n"));
    _EXP_CFLOW();
    while (1) {
        CALL(&printf, OBF("Password > "));
        if (CALL(&scanf, OBF("%99s"), buff) && strcmp(buff, OBF("top_10_password")) == 0) {
            CALL(&printf, OBF("Ok congrads. You did it. Now go outside & touch some grass\n"));
            CALL(&getchar);
            _EXP_CFLOW();
            break;
        } else {
            CALL(&printf, OBF("Nope. That's wrong ;(\n"));
        }
        _EXP_CFLOW();
    }

    return 0;
}