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

uint8_t asn1_demo[] = {0x30,0x81,0x9f,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8d,0x00,0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xd8,0x04,0x72,0x09,0xfe,0x57,0xcf,0x0f,0x50,0xb6,0x4f,0x6d,0x06,0xc7,0x02,0xf5,0x80,0xe5,0x4b,0x43,0x98,0x07,0x27,0x58,0x83,0x8e,0x55,0xbc,0x9a,0xab,0x60,0xf0,0x4a,0xd8,0x63,0x3a,0x8d,0x67,0x47,0x86,0x43,0x4f,0x40,0x59,0xc5,0x94,0x41,0x93,0x8d,0x81,0x67,0xf8,0xa9,0x57,0x56,0xbc,0x0d,0xc9,0x8d,0x81,0xff,0xb9,0x5d,0x0c,0x32,0x2f,0xe1,0xe7,0x35,0xc0,0x5b,0x2d,0x89,0x55,0x34,0xa6,0x6d,0x79,0x89,0x5b,0xb5,0xb2,0xd2,0x22,0xc2,0x00,0x89,0xa8,0xa3,0x25,0x6d,0xc3,0xbf,0xcd,0xd4,0x99,0xd7,0x8c,0xc9,0xa9,0x5e,0x02,0x10,0xc7,0xd1,0xe3,0x00,0x71,0xd0,0x8a,0xf6,0x81,0xcc,0x4e,0xe2,0xf7,0x2a,0x8a,0x12,0x71,0x6a,0x8d,0x3c,0xda,0x9a,0x53,0x7f,0x7f,0x02,0x03,0x01,0x00,0x01,};
// use the 'test.py' file in this example's root folder to generate more key structs for testing

int main(void)
{
	asn1_obj_t output[10] = {0};
	asn1_obj_t output2[10] = {0};
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
	size_t obj_ct = asn1_decode(asn1_demo, sizeof asn1_demo, output, 10);
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
	obj_ct = asn1_decode(output[2].data, output[2].len, output2, 10);
	sprintf(CEMU_CONSOLE, "\nDecode complete, %u objects parsed.\n", obj_ct);
	for(int i=0; i<obj_ct; i++)
		sprintf(CEMU_CONSOLE, "Obj %u, Tag Id: %u, Size: %u, Addr: %u\n", i, output2[i].tag, output2[i].len, output2[i].data);
	
	
	// Strip the first byte of modulus and you have the information you need for
	// rsa_encrypt().
    return 0;
}
