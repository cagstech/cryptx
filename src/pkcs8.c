
#include <stdint.h>
#include <cryptx.h>

#include "pkcs8.h"

uint8_t _pkcs_validator_keyinfo[2] = {0x06, 0x05};
uint8_t _pkcs_validator_publickey[2] = {0x03, 0x03};
uint8_t _pkcs_validator_privatekey[10] = {??, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, ??};


size_t cryptx_pkcs8_getdatalen(void *data, size_t len){
  size_t datalen;
  if((data == NULL) || (len == 0)) return 0;
  if(cryptx_asn1_decode(data, len, 0, NULL, &datalen, NULL) != ASN1_OK)
    return 0;
  return datalen;
}

pkcs_error_t cryptx_pkcs8_import_publickey(struct cryptx_pkcs8_publickey *pkcs,
                                           void *data, size_t len){
  if((data == NULL) ||
     (len == 0) ||
     (pkcs == NULL)) return PKCS_INVALID_ARG;
  if(sizeof(pkcs) < len) return PKCS_INVALID_STRUCT;
  
  // verify that PEM banner matches expectation
  char *test_str = "-----BEGIN PUBLIC KEY-----";
  if(strncmp(data, test_str, strlen(test_str)))
    return PKCS_INVALID_DATA;
  
  // strip PEM headers
  uint8_t *pem_start = data;
  while(*pem_start++ != '\n');
  uint8_t *pem_end = data + len;
  while(*pem_start-- != '\n');
  size_t pem_size = pem_end - pem_start;
  
  // decode PEM/Base64
  size_t der_size = pem_size * 8 / 6;
  uint8_t der_buf[der_size];
  cryptx_base64_decode(der_buf, pem_start, pem_size);
  
  // declare variables to hold ASN.1 metadata
  uint8_t tag;
  uint8_t *unwrap1, *unwrap2, *object;
  size_t unwrap1_len, unwrap2_len, object_len;
  asn1_error_t err = ASN1_OK;
  size_t w_offset = 0;    // location in struct to copy decoded data
  
  // decode containing SEQUENCE
  err = cryptx_asn1_decode(der_buf, der_size, 0, &tag, &unwrap1, &unwrap1_len);
  if(err || (cryptx_asn1_gettag(tag) != ASN1_SEQUENCE))
    return PKCS_INVALID_DATA;
  
  // decode algorithm ID and parameters
  for(int i=0; i<=PKCS_PARAMS; i++){
    err = cryptx_asn1_decode(unwrap1, unwrap1_len, i, &tag, &object_len, &object);
    if(err || (cryptx_asn1_gettag(tag) != _pkcs_validator_keyinfo[i]))
      return PKCS_INVALID_DATA;
    pkcs->info[i].data = &pkcs->raw_data[w_offset];
    pkcs->info[i].len = object_len;
    memcpy(&pkcs->raw_data[w_offset], object, object_len);
    w_offset += object_len;
  }
  
  // decode public key PKCS#1 structure
  err = cryptx_asn1_decode(unwrap1, unwrap1_len, PKCS_KEYINFO, &tag, &unwrap2_len, &unwrap2);
  if(err || (cryptx_asn1_gettag(tag) != ASN1_SEQUENCE))
    return PKCS_INVALID_DATA;
  
  for(int i=0; i<=PKCS_PUBKEY_EXPONENT; i++){
    err = cryptx_asn1_decode(unwrap2, unwrap2_len, i, &tag, &object_len, &object);
    if(err || (cryptx_asn1_gettag(tag) != _pkcs_validator_publickey[i]))
      return PKCS_INVALID_DATA;
    pkcs->publickey.info[i].data = &pkcs->raw_data[w_offset];
    pkcs->publickey.info[i].len = object_len;
    memcpy(&pkcs->raw_data[w_offset], object, object_len);
    w_offset += object_len;
  }
  return PKCS_OK;
}


void cryptx_pkcs8_destroy(struct cryptx_pkcs8_key *pkcs){
  memset(pkcs, 0, sizeof(pkcs));
}

