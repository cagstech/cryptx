#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <hashlib.h>

#define HASH_BLOCK_OUT_MAX  64
uint8_t hash_out_lens[] = {32};
bool hashlib_MGF1Hash(uint8_t* data, size_t datalen, uint8_t* outbuf, size_t outlen, uint8_t alg){
	uint32_t ctr = 0;
    size_t hash_len = hash_out_lens[alg];
	size_t copylen;
	uint8_t hash_digest[HASH_BLOCK_OUT_MAX], ctr_data[4];
	hash_ctx ctx_data, ctx_ctr;
	if(!hash_init(&ctx_data, alg)) return false;
	hash_update(&ctx_data, data, datalen);
	for(size_t printlen=0; printlen<outlen; printlen+=hash_len, ctr++){
		copylen = (outlen-printlen > hash_len) ? hash_len : outlen-printlen;
		//memcpy(ctr_data, &ctr, 4);
		ctr_data[0] = (uint8_t) ((ctr >> 24) & 0xff);
		ctr_data[1] = (uint8_t) ((ctr >> 16) & 0xff);
		ctr_data[2] = (uint8_t) ((ctr >> 8) & 0xff);
		ctr_data[3] = (uint8_t) ((ctr >> 0) & 0xff);
		memcpy(&ctx_ctr, &ctx_data, sizeof ctx_ctr);
		hash_update(&ctx_ctr, ctr_data, 4);
		hash_final(&ctx_ctr, hash_digest);
		memcpy(&outbuf[printlen], hash_digest, copylen);
	}
    return true;
}

