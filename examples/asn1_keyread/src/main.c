
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
#include <fileioc.h>
#include <cryptx.h>
#define CEMU_CONSOLE ((char*)0xFB0000)


void decode_item(void *ptr, size_t len, uint8_t level);

int main(void)
{
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nENCODEX ASN.1 Decoder Demo\n");
  uint8_t file;
  if(!(file=ti_Open("KeyF", "r"))) return 1;
  
  uint8_t *asn1_demo = ti_GetDataPtr(file) + 4;
  size_t asn1_len = ti_GetSize(file) - 4;
  
	decode_item(asn1_demo, asn1_len, 0);
  ti_Close(file);
}


void decode_item(void *ptr, size_t len, uint8_t level){
	asn1_error_t err = 0;
	int idx = 0;
	uint8_t tag = 0, *elem = NULL;
	size_t elem_len = 0;
	while(1) {
		err = cryptx_asn1_decode(ptr, len, idx, &tag, &elem_len, &elem);
		if(err == ASN1_END_OF_FILE) break;
		for(int i = 0; i<level; i++) sprintf(CEMU_CONSOLE, "| ");
		sprintf(CEMU_CONSOLE, "Tag:%u, Size:%u, Ptr:%p\n", tag, elem_len, elem);
		if(cryptx_asn1_get_form(tag)) decode_item(elem, elem_len, level+1);
		idx++;
	}
}
