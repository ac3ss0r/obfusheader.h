#include <stdio.h>
#include "../include/obfusheader.h"

int main() {
    printf(OBF("%s, %d, %c\n"), OBF("Test string"), OBF(123), OBF('c'));
    return 0;
}