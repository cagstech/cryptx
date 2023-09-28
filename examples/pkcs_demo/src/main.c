
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

uint8_t test_rsa[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0};

int main(void){
  struct cryptx_pkcs8_pubkeyinfo pub = {0};
  struct cryptx_pkcs8_privkeyinfo priv = {0};
  pkcs_error_t err;
  
  sprintf(CEMU_CONSOLE, "\n\n__TESTING PUBLIC KEYS__\n");
  for(int i=0; i<2; i++) {
    err = 0;
    uint8_t *keystr = public_keys[i];
    sprintf(CEMU_CONSOLE, "\n\npublic:\n");
    sprintf(CEMU_CONSOLE, "%s\n", keystr);
    err = cryptx_pkcs8_import_publickey(keystr, strlen(keystr), &pub);
    if(err){
      sprintf(CEMU_CONSOLE, "error: %u\n", err);
      continue;
    }
    hexdump(pub.objectid.bytes, pub.objectid.len, "object id");
    if(memcmp(pub.objectid.bytes, test_rsa, pub.objectid.len)==0){
      hexdump(pub.publickey.rsa.modulus.bytes, pub.publickey.rsa.modulus.len, "key data");
      sprintf(CEMU_CONSOLE, "public exponent: %u\n", pub.publickey.rsa.exponent);
    }
    else {
      hexdump(pub.publickey.ec.curveid.bytes, pub.publickey.ec.curveid.len, "curve id");
      hexdump(pub.publickey.ec.bytes, pub.publickey.ec.len, "key data");
      sprintf(CEMU_CONSOLE, "compressed: %u\n", pub.publickey.ec.compressed);
    }
  }
  
  sprintf(CEMU_CONSOLE, "\n\n__TESTING PRIVATE KEYS__\n");
  for(int i=0; i<2; i++) {
    err = 0;
    uint8_t *keystr = private_keys[i];
    sprintf(CEMU_CONSOLE, "\n\nprivate:\n");
    sprintf(CEMU_CONSOLE, "%s\n", keystr);
    err = cryptx_pkcs8_import_privatekey(keystr, strlen(keystr), &priv);
    if(err){
      sprintf(CEMU_CONSOLE, "error: %u\n", err);
      continue;
    }
    hexdump(priv.objectid.bytes, priv.objectid.len, "object id");
    if(memcmp(priv.objectid.bytes, test_rsa, priv.objectid.len)==0){
      hexdump(priv.privatekey.rsa.modulus.bytes, priv.privatekey.rsa.modulus.len, "modulus");
      sprintf(CEMU_CONSOLE, "public exponent: %u\n", priv.privatekey.rsa.public_exponent);
      hexdump(priv.privatekey.rsa.exponent.bytes, priv.privatekey.rsa.exponent.len, "private exponent");
      
      // additional
      hexdump(priv.privatekey.rsa.parts.p.bytes, priv.privatekey.rsa.parts.p.len, "P");
      hexdump(priv.privatekey.rsa.parts.q.bytes, priv.privatekey.rsa.parts.q.len, "Q");
      hexdump(priv.privatekey.rsa.parts.exp1.bytes, priv.privatekey.rsa.parts.exp1.len, "Exponent1");
      hexdump(priv.privatekey.rsa.parts.exp2.bytes, priv.privatekey.rsa.parts.exp2.len, "Exponent2");
      hexdump(priv.privatekey.rsa.parts.coeff.bytes, priv.privatekey.rsa.parts.coeff.len, "Coefficient");
    }
    else {
      hexdump(priv.privatekey.ec.curveid.bytes, priv.privatekey.ec.curveid.len, "curve id");
      hexdump(priv.privatekey.ec.private.bytes, priv.privatekey.ec.private.len, "private key");
      hexdump(priv.privatekey.ec.public.bytes, priv.privatekey.ec.public.len, "public key");
      sprintf(CEMU_CONSOLE, "compressed: %u\n", priv.privatekey.ec.public.compressed);
      
    }
  }
  
 
}


