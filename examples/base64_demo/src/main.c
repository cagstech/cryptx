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

uint8_t *encode = "light work";

int main(void)
{
	uint8_t out[100] = {0};
	uint8_t out2[100] = {0};
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nENCODEX Base64 Encoder Demo\n");

	sprintf(CEMU_CONSOLE, "\noriginal string len: %u\n", strlen(encode));
	size_t outlen = cryptx_base64_encode(encode, strlen(encode), out);
	sprintf(CEMU_CONSOLE, "\nEncode complete, output len: %u\n", outlen);
	sprintf(CEMU_CONSOLE, "%s\n", out);
	
	outlen = cryptx_base64_decode(out, strlen(out), out2);
	sprintf(CEMU_CONSOLE, "\nDecode complete, output len: %u\n", outlen);
	sprintf(CEMU_CONSOLE, "%s\n", out2);
	
	
    return 0;
}
