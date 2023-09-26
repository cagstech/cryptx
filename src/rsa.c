
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <hashlib.h>
#include <encrypt.h>
#include <add64.h>

#define RSA_MODULUS_MAX	256
#define RSA_SALT_SIZE	64
#define	ENCODE_START 	0
#define ENCODE_SALT 	(1 + ENCODE_START)
uint8_t hash_out_lens[] = {32};
size_t hashlib_RSAEncodeOAEP(const uint8_t* in, size_t len, uint8_t* out, size_t modulus_len, const uint8_t *auth, uint8_t alg){

	struct cryptx_hash_ctx ctx;
	if(!cryptx_hash_init(&ctx, alg)) return 0;
	size_t hash_len = ctx.digest_len;
	size_t min_padding_len = (hash_len<<1) + 2;
	size_t ps_len = modulus_len - len - min_padding_len;
	size_t db_len = modulus_len - hash_len - 1;
    size_t encode_lhash = ENCODE_SALT + hash_len;
    size_t encode_ps = encode_lhash + hash_len;
	uint8_t mgf1_digest[RSA_MODULUS_MAX];

    if(in==NULL) return 0;
    if(out==NULL) return 0;
    if(len==0) return 0;
    if(modulus_len > RSA_MODULUS_MAX) return 0;

	if((len + min_padding_len) > modulus_len) return 0;
	
	// set first byte to 00
	out[ENCODE_START] = 0x00;
	// seed next 32 bytes
	cryptx_csrand_fill(&out[ENCODE_SALT], hash_len);
	
	// hash the authentication string
	if(auth != NULL) cryptx_hash_update(&ctx, auth, strlen(auth));
	cryptx_hash_final(&ctx, &out[encode_lhash]);	// nothing to actually hash
	
	memset(&out[encode_ps], 0, ps_len);		// write padding zeros
	out[encode_ps + ps_len] = 0x01;			// write 0x01
	memcpy(&out[encode_ps + ps_len + 1], in, len);		// write plaintext to end of output
	
	// hash the salt with MGF1, return hash length of db
	cryptx_hash_mgf1(&out[ENCODE_SALT], hash_len, mgf1_digest, db_len, alg);
                
    // XOR hash with db
    for(size_t i=0; i < db_len; i++)
        out[encode_lhash + i] ^= mgf1_digest[i];
                    
    // hash db with MGF1, return hash length of RSA_SALT_SIZE
    cryptx_hash_mgf1(&out[encode_lhash], db_len, mgf1_digest, hash_len, alg);
                
    // XOR hash with salt
    for(size_t i=0; i<hash_len; i++)
        out[ENCODE_SALT + i] ^= mgf1_digest[i];
                    
                // Return the static size of 256
    return modulus_len;
}



size_t hashlib_RSADecodeOAEP(const uint8_t *in, size_t len, uint8_t* out, const uint8_t *auth, uint8_t alg){
  
    if(in==NULL) return 0;
    if(out==NULL) return 0;
    if(len==0) return 0;
    if(len > 256) return 0;
	struct cryptx_hash_ctx ctx;
	if(!cryptx_hash_init(&ctx, alg)) return 0;
	size_t hash_len = ctx.digest_len;
    size_t db_len = len - hash_len - 1;
    uint8_t sha256_digest[64];
    size_t encode_lhash = ENCODE_SALT + hash_len;
    size_t encode_ps = encode_lhash + hash_len;
    uint8_t mgf1_digest[RSA_MODULUS_MAX];
    size_t i;
	uint8_t tmp[256];
	
	memcpy(tmp, in, len);
                
    // Copy last 16 bytes of input buf to salt to get encoded salt
   // memcpy(salt, &in[len-RSA_SALT_SIZE-1], RSA_SALT_SIZE);
                
    // SHA-256 hash db
	cryptx_hash_mgf1(&tmp[encode_lhash], db_len, mgf1_digest, hash_len, alg);
                
    // XOR hash with encoded salt to return salt
    for(i = 0; i < hash_len; i++)
		tmp[ENCODE_SALT + i] ^= mgf1_digest[i];
                    
    // MGF1 hash the salt
    cryptx_hash_mgf1(&tmp[ENCODE_SALT], hash_len, mgf1_digest, db_len, alg);
                
    // XOR MGF1 of salt with encoded message to get decoded message
    for(i = 0; i < db_len; i++)
		tmp[encode_lhash + i] ^= mgf1_digest[i];
	
	// verify authentication
	if(auth != NULL) cryptx_hash_update(&ctx, auth, strlen(auth));
	cryptx_hash_final(&ctx, sha256_digest);
	if(!cryptx_digest_compare(sha256_digest, out, hash_len)) return 0;
	
	for(i = encode_ps; i < len; i++)
		if(tmp[i] == 0x01) break;
	if(i==len) return 0;
	i++;
	memcpy(out, &tmp[i], len-i);
   
   
    return len-i;
}


/*
#define MPRIME_LEN			(8 + 64 + 64)
#define MPRIME_OCTETS		0
#define MPRIME_MHASH		(MPRIME_OCTETS + 8)
//#define MPRIME_SALT			(MPRIME_MHASH + RSA_SALT_SIZE)

#define DB_END				(-1)
//#define DB_MPRIME_HASH		((DB_END) + (-RSA_SALT_SIZE))
//#define DB_SALT				((DB_MPRIME_HASH) + (-RSA_SALT_SIZE))
//#define DB_MASK_BYTE		((DB_SALT) + (-1))
//#define DB_PADDING_END		((DB_MASK_BYTE) + (-1))
size_t hashlib_RSAEncodePSS(
	const uint8_t* in,
	size_t len,
	uint8_t *out,
	size_t modulus_len,
	uint8_t *salt,
    uint8_t alg){
	
	uint8_t mprime_buf[MPRIME_LEN];
	hash_ctx ctx;
    size_t hash_len = hash_out_lens[alg];
	uint8_t hMprime[64];
	uint8_t mgf1_digest[RSA_MODULUS_MAX];
	size_t db_len = modulus_len - hash_len - 1;
	size_t ps_len = db_len - hash_len - 1;
    
    size_t mprime_len = 8 + (hash_len<<1);
    size_t mprime_salt = MPRIME_MHASH + hash_len;
    size_t db_mprime_hash = DB_END - hash_len;
    size_t db_salt = db_mprime_hash - hash_len;
    size_t db_mask_byte = db_salt - 1;
    size_t db_padding_end = db_mask_byte - 1;
	
	// errors
	if((in == NULL) || (out == NULL)) return 0;
	if((modulus_len > 256) || (modulus_len < 128)) return 0;
	if(len==0) return 0;
	
	// init buffers to 0
	memset(out, 0, modulus_len);
	memset(mprime_buf, 0, MPRIME_LEN);
	// hash message, write to MHASH block
	if(!hash_init(&ctx, alg)) return 0;
	hash_update(&ctx, in, len);
	hash_final(&ctx, &mprime_buf[MPRIME_MHASH]);
	
	// write in random oracle passed, or generate one
	if(salt != NULL)
		memcpy(&mprime_buf[mprime_salt], salt, hash_len);
	else
		csrand_fill(&mprime_buf[mprime_salt], hash_len);
	// copy salt to DB as well
	memcpy(&out[modulus_len + db_salt], &mprime_buf[mprime_salt], hash_len);
	
	// write masking and ending bytes
	out[modulus_len + db_mask_byte] = 0x01;
	out[modulus_len + DB_END] = 0xbc;
		
	// hash M' buffer
	hash_init(&ctx, alg);
	hash_update(&ctx, mprime_buf, mprime_len);
	hash_final(&ctx, hMprime);
	
	// write hash to output hash block
	memcpy(&out[modulus_len + db_mprime_hash], hMprime, hash_len);
	
	// MGF1 the hash
	hash_mgf1(hMprime, hash_len, mgf1_digest, db_len, alg);
	
	// xor the hash with the output db block
	for(size_t i = 0; i < db_len; i++)
		out[i] ^= mgf1_digest[i];
		
		
	return modulus_len;
}
*/
#define RSA_PUBLIC_EXP  65537
rsa_error_t hashlib_RSAEncrypt(const uint8_t* msg, size_t msglen, const uint8_t* pubkey, size_t keylen, uint8_t *ct, uint8_t oaep_hash_alg){
    uint8_t spos = 0;
    if(msg==NULL || pubkey==NULL || ct==NULL) return RSA_INVALID_ARG;
    if(keylen<128 || keylen>256 || (!(pubkey[keylen-1]&1))) return RSA_INVALID_MODULUS;
    while(pubkey[spos]==0) {ct[spos++] = 0;}
    if(msglen == 0 || (msglen + 66 > (keylen-spos))) return RSA_INVALID_MSG;
    if(!hashlib_RSAEncodeOAEP(msg, msglen, &ct[spos], keylen-spos, NULL, oaep_hash_alg)) return RSA_ENCODING_ERROR;
    powmod((uint8_t)keylen, ct, RSA_PUBLIC_EXP, pubkey);
    return RSA_OK;
}
