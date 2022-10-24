/**
 * @file encodex.h
 * @brief Provides support for various data encoding schemes
 *
 *@author Anthony @e ACagliano Cagliano
 */

#ifndef ENCODEX_H
#define ENCODEX_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


// ##########################
// ###### ASN.1 Parser ######
// ##########################
 
/*************************************************
 * @typedef asn1_obj_t
 * Defines a struct type for extracting ASN.1 element metadata
 * See asn1_decode()
 */
typedef struct _asn1_obj_t {
	uint8_t tag;			/**< Defines the ASN.1 element tag (low 5 bits of the id) */
	uint8_t f_class;		/**< Defines the ASN.1 class (high 2 bits of the id) */
	bool f_form;			/**< Defines the ASN.1 construction scheme (bit 5 of the id) */
	size_t len;				/**< Defines the length of the data portion of the element */
	uint8_t *data;			/**< Defines a pointer to the data portion of the element */
} asn1_obj_t;

/*********************************
 * @enum ASN1\_TYPES
 * Defines tag identifiers for ASN.1 encoding
 * See @b asn1_obj_t.tag
 */
enum ASN1_TYPES {
	ANS1_RESVD = 0,
	ANS1_BOOLEAN,
	ANS1_INTEGER,
	ANS1_BITSTRING,
	ANS1_OCTETSTRING,
	ANS1_NULL,
	ANS1_OBJECTID,
	ANS1_OBJECTDESC,
	ANS1_INSTANCE,
	ANS1_REAL,
	ANS1_ENUMERATED,
	ASN1_EMBEDDEDPDV,
	ASN1_UTF8STRING,
	ASN1_RELATIVEOID,
	ASN1_SEQUENCE = 16,
	ASN1_SET,
	ASN1_NUMERICSTRING,
	ASN1_PRINTABLESTRING,
	ASN1_TELETEXSTRING,
	ASN1_VIDEOTEXSTRING,
	ASN1_IA5STRING,
	ASN1_UTCTIME,
	ASN1_GENERALIZEDTIME,
	ASN1_GRAPHICSTRING,
	ASN1_VISIBLESTRING,
	ASN1_GENERALSTRING,
	ASN1_UNIVERSALSTRING,
	ASN1_CHARSTRING,
	ASN1_BMPSTRING
};

/**********************************
 * @enum ASN1\_CLASSES
 * Defines class identifiers for ASN.1 encoding.
 * See @b asn1_obj_t.f_class
 */
enum ASN1_CLASSES {
	ASN1_UNIVERSAL,
	ASN1_APPLICATION,
	ASN1_CONTEXTSPEC,
	ASN1_PRIVATE
};

/********************
 * @enum ASN1\_FORMS
 * Defines form identifiers for ASN.1 encoding.
 * See @b asn1_obj_t.f_form
 */
enum ASN1_FORMS {
	ASN1_PRIMATIVE,
	ASN1_CONSTRUCTED
};

/****************************************************************
 * @brief ASN.1 Decoder
 * Parses ASN.1 encoded data and returns metadata into an array of structs.
 * This function calls itself if it encounters an object of @b constructed type..
 * For DER-formatted RSA public keys, you will need to call this function twice.
 * The second time should be on the @b ANS1_BITSTRING that encodes the modulus
 * and public exponent.
 * @param asn1_data Pointer to ASN.1-encoded data
 * @param asn1_len The length of the encoded data
 * @param objs Pointer to an array of @b asn1_obj_t structs to fill with decoded data
 * @param iter_count Maximum number of ASN.1 elements to process before returning
 */
size_t asn1_decode(void *asn1_data, size_t asn1_len, asn1_obj_t *objs, size_t iter_count);


#endif
