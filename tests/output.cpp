#include <stdio.h>
#include "../include/obfusheader.h"

int main() {
    printf(OBF("%s, %d, %c"), OBF("Test"), OBF(123), OBF('c'));
    return 0;
}