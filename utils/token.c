#include "token.h"
#include "../logger/logger.h"

#include <string.h>
#include <sodium.h>

/**
 * Fonction qui hash un token 
 */
int hash_token(const char *token_bytes, size_t token_bytes_len, char *out, size_t out_len){
    
    if(out_len < crypto_hash_sha256_BYTES*2+1){
        LOG_ERROR("The out lenght is less than the hash token");
        return -1;
    }

    // 3. Hash SHA-256 du token
    unsigned char hash_sha256[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash_sha256, token_bytes, token_bytes_len);

    // 4. Conversion du hash en HEX (à stocker en DB)
    sodium_bin2hex(out, out_len, hash_sha256, sizeof(hash_sha256));

    sodium_memzero(hash_sha256, sizeof(hash_sha256));
    return 0;
}