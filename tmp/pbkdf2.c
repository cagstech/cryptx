#include <hashlib.h>
#include <stdint.h>
#include <tice.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


#define MIN(x, y)   ((x) < (y)) ? (x) : (y)
#define HASH_BLOCK_OUT_MAX  64
uint8_t hash_out_lens[] = {32};

bool hashlib_PBKDF2(const uint8_t* password, size_t plen, uint8_t* out, size_t keylen, const uint8_t* salt, size_t salt_len, size_t iter_count, uint8_t alg){

    uint8_t hash_buffer[HASH_BLOCK_OUT_MAX];
    uint8_t hash_composite[HASH_BLOCK_OUT_MAX];
    size_t hash_len = hash_out_lens[alg];
    uint8_t c[4];
    hmac_ctx hmac = {0};
    hmac_ctx bck;
    size_t outlen;
    uint32_t counter = 1;
    
    if(password==NULL || out==NULL) return false;
    if(plen==0) return false;
    if(iter_count<1) return false;
    if(keylen==0) return false;
    //HASH = sha256
    // DK = T(i) for i in 0 => (keylen/HASH), concat
    if(!hmac_init(&hmac, password, plen, alg)) return false;
    memcpy(&bck, &hmac, sizeof bck);
    for(outlen = 0; outlen < keylen; outlen+=hash_len, counter++){
        //T(i) = F(password, salt, c, i) = U1 xor U2 xor ... xor Uc
            //U1 = PRF1(Password, Salt + INT_32_BE(i))
            //U2 = PRF(Password, U1)
            //⋮
            //Uc = PRF(Password, Uc)
        size_t copylen = MIN(keylen-outlen, hash_len);
        c[0] = (counter >> 24) & 0xff;
		c[1] = (counter >> 16) & 0xff;
		c[2] = (counter >> 8) & 0xff;
		c[3] = counter & 0xff;
        hmac_update(&hmac, salt, salt_len);
        hmac_update(&hmac, c, sizeof c);
        hmac_final(&hmac, hash_buffer);
        memcpy(hash_composite, hash_buffer, hash_len);
        for(size_t ic=1; ic<iter_count; ic++){
            memcpy(&hmac, &bck, sizeof hmac);
            hmac_update(&hmac, hash_buffer, hash_len);
            hmac_final(&hmac, hash_buffer);
            for(uint8_t j=0; j < hash_len; j++)
                hash_composite[j] ^= hash_buffer[j];
        }
        memcpy(&out[outlen], hash_composite, copylen);
        memcpy(&hmac, &bck, sizeof hmac);
    }
    return true;
}
