#ifndef PASSWORD_H
#define PASSWORD_H

#include <string.h>

#include "../models/user.h"

int hash_password(const char *pwd, char *out, size_t out_len);

#endif