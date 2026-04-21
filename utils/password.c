#include "password.h"
#include "../logger/logger.h"

#include <string.h>
#include <sodium.h>

int hash_password(const char *pwd, char *out, size_t out_len){
    if(out_len < crypto_pwhash_STRBYTES){
        LOG_ERROR("The out lenght is less than the hash password");
        return -1;
    }

    int hash_result = crypto_pwhash_str(out, pwd, strlen(pwd), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
    if(hash_result != 0){
        LOG_ERROR("There is a problem during the password hash");
        return -1;
    }
    return 0;
}