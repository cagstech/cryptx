/*
#include <cryptx.h>

typedef uint8_t BIGINT[CRYPTX_GF2_INTLEN];

typedef enum _ecdsa_errors {
  ECDSA_OK,
  ECDSA_INVALID_ARG,
  ECDSA_HASH_ERROR,
  ECDSA_PRIVKEY_INVALID,
  ECDSA_RPUBKEY_INVALID,
  ECDSA_HASH_ERROR
} ecdsa_error_t;

ecdsa_error_t ecdsa_sign(uint8_t *data, size_t datalen, uint8_t *signature, uint8_t *privkey, uint8_t hash_algorithm){
  
  if((privkey==NULL) ||
     (data==NULL) ||
     (datalen==0) ||
     (signature==NULL))
    return ECDSA_INVALID_ARG;
  
  cryptx_hash_ctx hash;
#define ECDSA_DIGEST_MAXLEN 32
  uint8_t hdigest[ECDSA_DIGEST_MAXLEN];
  if(!cryptx_hash_init(&hash, hash_algorithm))
    return ECDSA_HASH_ERROR;
  cryptx_hash_update(&hash, data, datalen);
  cryptx_hash_final(&hash, hdigest);
  
  
  int success = 0;
  
  BIGINT k = {0}, z;
  
  //bitvec_copy(z, (uint32_t*)hash);
  memcpy(z, hdigest, CRYPTX_GF2_INTLEN);
  // constrain z to degree of poly
  z[29] &= 1;
  
regen_k:
  // 3) Select a cryptographically secure random integer k from [1, n-1]
  cryptx_csrand_fill(k, ECC_PRV_KEY_SIZE-1)
  
  // 4) Calculate the curve point (x1, y1) = k * G
  struct Point p1;
  rmemcpy(p1.x, sect233k1.G.x, sizeof sect233k1.G.x);
  rmemcpy(p1.y, sect233k1.G.y, sizeof sect233k1.G.y);
  point_mul_scalar(p1, k, (ECC_PRV_KEY_SIZE)<<3);
  // p1.x = r
  // p1.y = s
  
  // 5) Calculate r = x1 mod n. if (r == 0) goto 3
  if (bigint_iszero(p1.x)) goto regen_k;
  
  // 6) s = inv(k) * (z + (r * d)) mod n ==> if (s == 0) goto 3
  bigint_invert(p1.y, k);                     // s = inv(k)
  bigint_mul(p1.x, p1.x, (uint32_t*)private_key); // r = (r * d)
  gf2field_add(r, r, z);                  // r = z + (r * d)
  
  nbits = bitvec_degree(r); // r = r mod n
  for (i = (nbits - 1); i < BITVEC_NBITS; ++i)
  {
    printf("reduction r\n");
    bitvec_clr_bit(r, i);
  }
  
  gf2field_mul(s, s, r);                  // s = inv(k) * (z * (r * d))
  
  nbits = bitvec_degree(s); // s = s mod n
  for (i = (nbits - 1); i < BITVEC_NBITS; ++i)
  {
    printf("reduction s\n");
    bitvec_clr_bit(s, i);
  }
  
  if (!bitvec_is_zero(s))
  {
    bitvec_copy((uint32_t*)signature, r);
    bitvec_copy((uint32_t*)(signature + ECC_PRV_KEY_SIZE), s);
    success = 1;
  }
}
}
return success;
}
}


*/
