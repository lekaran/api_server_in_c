#ifndef TOKEN_H
#define TOKEN_H

#include <string.h>

int hash_token(const char *token_bytes, size_t token_bytes_len, char *out, size_t out_len);

#endif