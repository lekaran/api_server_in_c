#ifndef USER_H
#define USER_H

#include <sodium.h>

#define ID_MAX 37
#define USERNAME_MAX 51
#define FIRST_NAME_MAX 101
#define LAST_NAME_MAX 101
#define PASSWORD_HASH_MAX 256
#define DATETIME_MAX 20

_Static_assert(PASSWORD_HASH_MAX >= crypto_pwhash_STRBYTES,"PASSWORD_HASH_MAX is less then the libsodium need");

// Model User
typedef struct {
    char id[ID_MAX];          
    char username[USERNAME_MAX];               
    char first_name[FIRST_NAME_MAX];
    char last_name[LAST_NAME_MAX];
    char password_hash[PASSWORD_HASH_MAX];
    char created_at[DATETIME_MAX]; 
    char updated_at[DATETIME_MAX];
} user_t;

#endif