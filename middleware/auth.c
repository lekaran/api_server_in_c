#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>   // pour strcmp

// Ici un exemple simple : un token fixe
void verify_token(const int token) {
    printf("Hello from middleware module : %d\n", token);
}
