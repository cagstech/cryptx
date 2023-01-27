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
#include <encodex.h>
#define CEMU_CONSOLE ((char*)0xFB0000)

uint8_t asn1_demo[] = {0x30,0x81,0x9f,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8d,0x00,0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xc0,0x3c,0xa0,0x1c,0x0b,0x0e,0xbe,0xb0,0x64,0x62,0xfc,0x2e,0x0e,0x8d,0x04,0x9d,0xc1,0xa7,0xc7,0xce,0x88,0x8d,0x85,0x87,0x6a,0x41,0x93,0x45,0x25,0x23,0x25,0x38,0x74,0xce,0x4f,0xf1,0x46,0xf5,0x3b,0x94,0x19,0xb2,0x1d,0x6d,0xfc,0xa0,0x46,0x04,0x64,0xc6,0xb2,0x33,0x77,0x2f,0xb9,0x89,0x33,0x6a,0xce,0x84,0x8a,0x5a,0xff,0x88,0x1f,0x03,0x38,0x31,0x1d,0xe6,0x08,0xdd,0xd0,0xae,0x86,0xfd,0xf5,0xd9,0x25,0x4f,0x82,0x1c,0x93,0xa4,0xcc,0x32,0x22,0x67,0xa2,0x16,0x68,0xb9,0xd6,0xae,0xe4,0xb2,0xee,0x80,0x93,0xb1,0x4a,0x2b,0x80,0x27,0x27,0xfd,0x99,0x18,0x90,0xb6,0xe2,0x97,0x2a,0x14,0x51,0x02,0xca,0x73,0x36,0x41,0x52,0x18,0xdc,0xa8,0xe8,0x69,0x44,0x09,0x02,0x03,0x01,0x00,0x01,};
// use the 'test.py' file in this example's root folder to generate more key structs for testing

int main(void)
{
	struct cryptx_asn1_obj output[10] = {0};
	struct cryptx_asn1_obj output2[10] = {0};
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nENCODEX ASN.1 Decoder Demo\n");

	// parse ASN.1 encoded data
	/*
	 This call to asn1_decode will return 3 objects.
	 1. pkcs#1IdString
	 2. nullObject
	 3. RSAData
	 This is because any tag with the constructed bit set will be automatically
	 deconstructed further, but the BIT STRING object does not have this tag set.
	 You will need to then call asn1_decode on this object specifically to break it down further.
	 */
	size_t obj_ct = cryptx_asn1_decode(asn1_demo, sizeof asn1_demo, output, 10);
	sprintf(CEMU_CONSOLE, "\nDecode complete, %u objects parsed.\n", obj_ct);
	for(int i=0; i<obj_ct; i++)
		sprintf(CEMU_CONSOLE, "Obj %u, Tag Id: %u, Size: %u, Addr: %u\n", i, output[i].tag, output[i].len, output[i].data);
	
	/*
	 For reasons unknown, DER encodes the integer modulus and public exponent as a BIT STRING
	 with a single byte of 0x00 padding, followed by a SEQUENCE containing the modulus and
	 exponent.
	 Also the modulus itself is usually prepended with a single 0x00 byte as well.
	 This call to asn1_decode will return 2 objects.
	 1. modulus
	 2. exponent
	 */
	obj_ct = cryptx_asn1_decode(output[2].data, output[2].len, output2, 10);
	sprintf(CEMU_CONSOLE, "\nDecode complete, %u objects parsed.\n", obj_ct);
	for(int i=0; i<obj_ct; i++)
		sprintf(CEMU_CONSOLE, "Obj %u, Tag Id: %u, Size: %u, Addr: %u\n", i, output2[i].tag, output2[i].len, output2[i].data);
	
	
	// Strip the first byte of modulus and you have the information you need for
	// rsa_encrypt().
    return 0;
}
