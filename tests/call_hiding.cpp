#include <windows.h>
#include "../include/obfusheader.h"

int main() {
    HANDLE stdOut = OBFUSCALL("kernel32.dll", "GetStdHandle", HANDLE(*)(DWORD))(STD_OUTPUT_HANDLE);
    if (stdOut != NULL && stdOut != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        const char * message = OBF("12345");
        OBFUSCALL("kernel32.dll", "WriteConsoleA", HANDLE(*)(HANDLE, const char*, DWORD, LPDWORD, LPVOID))
                 (stdOut, message, strlen(message), &written, NULL);
    }
    return 0;
}