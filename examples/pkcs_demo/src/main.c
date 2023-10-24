
/*
 *--------------------------------------
 * Program Name: DEMO
 * Author: Anthony Cagliano
 * License: GPL3
 * Description: ASN.1 Decoder Demo
 *--------------------------------------
 *
 * This program demonstrates how to extract public key information from
 * a DER-encoded RSA key format. The DER-formatted public key exported by
 * pycryptodomex's RSA module looks like this:
 
 
 SEQUENCE {
 RSAMetadata ::= SEQUENCE {
 pkcs#1IdString		OBJECT IDENTIFIER
 nullObject			NULL
 }
 RSAData ::= BIT STRING {
 RSAPublicKey ::= SEQUENCE {
 modulus           INTEGER,  -- n
 publicExponent    INTEGER   -- e
 }
 }
 }
 
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <cryptx.h>
#define CEMU_CONSOLE ((char*)0xFB0000)

uint8_t *public_keys[2] = {
  "-----BEGIN PUBLIC KEY-----\nMFIwEAYHKoZIzj0CAQYFK4EEABoDPgAEAYBgPlRKtPOVNaqGdwE1Sghr69rAqV/+Zt0/rKvBAL4WQ3lGeRUcndTgKs7a8E9LyCn0+3O+Xb2qa8a7\n-----END PUBLIC KEY-----",
  "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqatHpZSVp2EfNG81DDf4V9vYUHJeoaxlDJLkCikNqGubXJxYUO57fpcY6sKiYgwnebtdyG8PJl/xUaTEsUYpL5pwhh96gbqf3Mu/RG2SmxsGxX+jA+GW6FTJRdWJVrHUv+OkkNVAC5LdznOrxhHWVMgPC0Ymoq4OYXEylcEgXswIDAQAB\n-----END PUBLIC KEY-----"
};

uint8_t *private_keys[2] = {
  "-----BEGIN PRIVATE KEY-----\nMH0CAQAwEAYHKoZIzj0CAQYFK4EEABoEZjBkAgEBBB1p1KPHFtkCORyRHawCBCE5FvkVbMsKkPZ+dY7TRKFAAz4ABAGAYD5USrTzlTWqhncBNUoIa+vawKlf/mbdP6yrwQC+FkN5RnkVHJ3U4CrO2vBPS8gp9Ptzvl29qmvGuw==\n-----END PRIVATE KEY-----",
  "-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALnUjWmu2yNk5o0ed3Xj9TgpCDJ+pCxLTqs8699iTm66XNdM40qZr9M1Hxh6xLfxBWbvrXb8LWiRVqN6QFNOYdnpMFC1D/Rqy1C1HQd5ukfKSHRekWZ3y8raxVcJejJndqP0SUoTRPpg3CFd5bqIjXVQS/YdMxxEr161ffsEFCjHAgMBAAECgYAXrSsvUeX9xndRd5ZE4Px3YVL4DAai1h1519M9rOrNVNVLYTJ8aMRsJpKFre6uePj1OohhZpPqhMoDHipf8taokv5YlwUVbYLvNq6vtr03BNpt4bvXClOvlAZmkK4LIby773FgvJreLGlK4sJYtpUp+u2XrNTFplKW5mY8o8qREQJBAPY4/kPEtYbgQqQ415v3U/Ib5h4wOuRV4QV2XbFfwy9S1ISM1uRexFc6jn59YJOvWI/tzKcByccq99ex/d3wzF0CQQDBNaIc/hg9+3c8rM4k3HfMHIeAZ0c5m7/HRHh7tcHSDPLvDVJwtHV2PZYupzfGNXjomuiyk5lmo3PGJ6Bf/BdzAkAxLd0LaCTh1bU52+ikzFfGCfCCoxuAM+8ICkZYgUoZD7BG8WKSpqMM0TNY7G330ZQc22B/Ewpcb6alPHX6eHg5AkEApcD9cyIKaiJyCPu3XqhFnjZbiS0RTbrwrGNxebBUt3+karFjKI2ot+feD+glUUZOlD9RouI9mHBhwn38eFwtQQJAQoQfKgOihyLwzSukUR/q5t1UB0i98RZfqSvaoXh4buooRDiNbnWTeq4fYdkKZutzuyoeGozJuyDMCROUrisGlQ==\n-----END PRIVATE KEY-----"
};

void hexdump(uint8_t *addr, size_t len, char *label){
  if(label) sprintf(CEMU_CONSOLE, "\n%s\n", label);
  else sprintf(CEMU_CONSOLE, "\n");
  for(size_t rem_len = len, ct=1; rem_len>0; rem_len--, addr++, ct++){
    sprintf(CEMU_CONSOLE, "\\x%02X", *addr);
    if(!(ct%CRYPTX_BLOCKSIZE_AES)) sprintf(CEMU_CONSOLE, "\n");
  }
  sprintf(CEMU_CONSOLE, "\n");
}

char ec_privkey_fields[][10] = {
  "curveid",
  "version",
  "privkey",
  "pubkey"
};
char rsa_privkey_fields[][12] = {
  "version",
  "modulus",
  "public exp",
  "exponent",
  "p",
  "q",
  "exp1",
  "exp2",
  "coeff"
};
char ec_pubkey_fields[][12] = {
  "curveid",
  "pubkey"
};
char rsa_pubkey_fields[][12] = {
  "modulus",
  "exponent",
};

int main(void){
  struct cryptx_pkcs8_pubkey *pub;
  struct cryptx_pkcs8_privkey *priv;
  
  sprintf(CEMU_CONSOLE, "\n---------TESTING PUBLIC KEYS--------\n");
  for(int i=0; i<2; i++) {
    uint8_t *keystr = public_keys[i];
    sprintf(CEMU_CONSOLE, "\n%s\n", keystr);
    pub = cryptx_pkcs8_import_publickey(keystr, strlen(keystr), malloc);
    if(pub && !pub->error){
      hexdump(pub->objectid.data, pub->objectid.len, "object id");
      if(memcmp(pub->objectid.data, cryptx_pkcs8_objectid_rsa, pub->objectid.len)==0){
        for(int i=0; i<PKCS8_PUBLIC_RSA_FIELDS; i++)
          hexdump(pub->publickey.rsa_fields[i].data, pub->publickey.rsa_fields[i].len, rsa_pubkey_fields[i]);
      }
      else if(memcmp(pub->objectid.data, cryptx_pkcs8_objectid_ec, pub->objectid.len)==0){
        for(int i=0; i<PKCS8_PUBLIC_EC_FIELDS; i++)
          hexdump(pub->publickey.ec_fields[i].data, pub->publickey.ec_fields[i].len, ec_pubkey_fields[i]);
      }
    }
    cryptx_pkcs8_free_publickey(pub, free);
  }
  
  sprintf(CEMU_CONSOLE, "\n--------TESTING PRIVATE KEYS--------\n");
  for(int i=0; i<2; i++) {
    uint8_t *keystr = private_keys[i];
    sprintf(CEMU_CONSOLE, "\n%s\n", keystr);
    priv = cryptx_pkcs8_import_privatekey(keystr, strlen(keystr), malloc);
    if(priv && !priv->error){
      hexdump(priv->objectid.data, priv->objectid.len, "object id");
      if(memcmp(priv->objectid.data, cryptx_pkcs8_objectid_rsa, priv->objectid.len)==0){
        for(int i=0; i<PKCS8_PRIVATE_RSA_FIELDS; i++)
          hexdump(priv->privatekey.rsa_fields[i].data, priv->privatekey.rsa_fields[i].len, rsa_privkey_fields[i]);
      }
      else if(memcmp(priv->objectid.data, cryptx_pkcs8_objectid_ec, priv->objectid.len)==0){
        for(int i=0; i<PKCS8_PRIVATE_EC_FIELDS; i++)
          hexdump(priv->privatekey.ec_fields[i].data, priv->privatekey.ec_fields[i].len, ec_privkey_fields[i]);
      }
    }
    cryptx_pkcs8_free_publickey(priv, free);
  }
}


