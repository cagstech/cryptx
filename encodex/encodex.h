/**
 * @file encodex.h
 * @brief Provides support for various data encoding schemes common to cryptography.
 * @author Anthony @e ACagliano Cagliano
 *
 * A library providing encoding support for various data formats
 * 1. ASN.1 parser
 * 2. Base64 encoding/decoding
 * 3. BPP
 */

#ifndef encodex_h
#define encodex_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


//**************************************************************************************
/*	ASN.1 Parser
	ASN stands for Abstract Syntax Notation.
	It is a standard notation language for defining data structures.
	It is commonly used for the encoding of key data by various cryptography libraries.
	Ex: DER keyfile format is a serialization standard for ASN.1. */

/*********************************
 * @enum CRYPTX\_ASN1\_TYPES
 * Defines tag identifiers for ASN.1 encoding
 * See @b cryptx_asn1_obj.tag.
 */
enum CRYPTX_ASN1_TYPES {
	ASN1_RESVD = 0,				/**< RESERVED */
	ASN1_BOOLEAN,				/**< defines a BOOLEAN object */
	ASN1_INTEGER,				/**< defines an INTEGER object */
	ASN1_BITSTRING,				/**< defines a BIT STRING object */
	ASN1_OCTETSTRING,			/**< defines an OCTET STRING object */
	ASN1_NULL,					/**< defines a NULL object (0 size, no data) */
	ASN1_OBJECTID,				/**< defines an OBJECT IDENTIFIER */
	ASN1_OBJECTDESC,			/**< defines an OBJECT DESCRIPTION */
	ASN1_INSTANCE,				/**< defines an INSTANCE */
	ASN1_REAL,					/**< defines a REAL object */
	ASN1_ENUMERATED,
	ASN1_EMBEDDEDPDV,
	ASN1_UTF8STRING,
	ASN1_RELATIVEOID,
	ASN1_SEQUENCE = 16,			/**< defines a SEQUENCE */
	ASN1_SET,					/**< defines a SET */
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
 * @enum CRYPTX\_ASN1\_CLASSES
 * Defines class identifiers for ASN.1 encoding.
 */
enum CRYPTX_ASN1_CLASSES {
	ASN1_UNIVERSAL,			/**< tags defined in the ASN.1 standard. Most use cases on calc will be this. */
	ASN1_APPLICATION,		/**< tags unique to a particular application. */
	ASN1_CONTEXTSPEC,		/**< tags that need to be identified within a particular, well-definded context. */
	ASN1_PRIVATE			/**< reserved for use by a specific entity for their applications. */
};

/**********************************
 * @enum CRYPTX\_ASN1\_FORMS
 * Defines forms for ASN.1 encoding.
 */
enum CRYPTX_ASN1_FORMS {
	ASN1_PRIMITIVE,			/**< this element should contain no nested elements. */
	ASN1_CONSTRUCTED,		/**< this element contains nested elements. */
};

/// Returns the 2-bit tag class flag. See @b CRYPTX_ASN1_CLASSES above.
#define CRYPTX_ASN1_CLASS(tag)		(((tag)>>6) & 0b11)

/// Returns the 1-bit tag form (1 = constructed, 0 = primitive)
#define CRYPTX_ASN1_FORM(tag)		(((tag)>>5) & 1)

/*********************************
 * @enum asn1\_error\_t
 * Defines error codes from the ASN.1 parser
 */
typedef enum {
	ASN1_OK,				/**< No errors occured. */
	ASN1_END_OF_FILE,		/**< End of ASN.1 data stream reached. Not an error. */
	ASN1_INVALID_ARG,		/**< One or more arguments invalid. */
	ASN1_LEN_OVERFLOW,		/**< Length of an element overflowed arch size\_t allowance. Remainder of data stream unparsable. */
} asn1_error_t;

/************************************************************************
 * @brief Decodes the ASN.1 data at the given address. Seeks to an element from the front of the data.
 * @param data_start	Pointer to a block of ASN.1-encoded data.
 * @param data_len		Length of ASN.1-encoded block.
 * @param seek_to		Number of ASN.1 elements to skip before returning one.
 * @param element_tag	Masked tag value of the returned element.
 * @param element_len	Length of the returned element.
 * @param element_data	Pointer to the data of the returned element.
 * @returns				An @b asn1_error_t indicating the status of the operation.
 * @note @b ASN1_END_OF_FILE will be returned if @b seek_to is invalid.
 * @note ASN.1 is a tree structure. You can use the @b element_data and @b element_len parameters
 * returned by this function to iterate further up the tree. To see if an element is of a type for which this is
 * valid, check the return value of @b CRYPTX_ASN1_FORM(element_tag).
 */
asn1_error_t cryptx_asn1_decode(
					void *data_start,
					size_t data_len,
					uint8_t seek_to,
					uint8_t *element_tag,
					size_t *element_len,
					void **element_data);


//**************************************************************************************
/*	Base64 Parsing
	
	Base64 encodes data in sextets (where each byte corresponds to 6 bits
	of the input stream) which is then mapped to one of 64 printable
	characters, or the = padding character. Base64 is often used to encode
	cryptographic data such as the PEM key format, bcrypt, and more. */

/***************************************************************
 * @brief Converts an octet-encoded byte stream into a sextet-encoded byte stream.
 * @param dest Pointer to output sextet-encoded data stream.
 * @param src Pointer to input octet-encoded data stream.
 * @param len Length of octet-encoded data stream.
 * @note @b dest should be at least  @b len \* 4 / 3 bytes large.
 * @returns Length of output sextet.
 */
size_t cryptx_base64_encode(void *dest, const void *src, size_t len);

/***************************************************************
 * @brief Converts a sextet-encoded byte stream into a octet-encoded byte stream.
 * @param dest Pointer to output octet-encoded data stream.
 * @param src Pointer to input sextet-encoded data stream.
 * @param len Length of sextet-encoded data stream.
 * @note @b dest should be at least @b len \* 3 / 4 bytes large.
 * @returns Length of output octet.
 */
size_t cryptx_base64_decode(void *dest, const void *src, size_t len);


//**************************************************************************************
/*	BPP Byte Packing
 
	Bits-per-pixel is a a form of data compression in which only the active bits
	of a series of bytes are retained and the bytes are compressed such that each
	octet contains multiple "bytes" worth of data.
 
	For example, imagine a 4-byte long data stream with possible values 0x00 - 0x03.
	In this scheme, only the low 2 bits of each byte are actually used:
	(0x00 = 0b00000000, 0x01 = 0b00000001, 0x02 = 0b00000010, 0x03 = 0b00000011).
	This means we are wasting 6 bits, or 75% of the data used to represent it.
	The data can be compressed into a more space-efficient 2-bpp format (2 bits-per-pixel). */

/*******************************************************************
 * @brief Encodes an octet-encoded byte stream into a @p bpp bit encoded byte stream.
 * @param dest Pointer to output data stream.
 * @param src Pointer to input data stream, with byte values expressible within @b bpp bits.
 * @param len Length of encoded (@p dest) data stream. (@p bpp / 8 the size of src)
 * @param bpp Number of bits-per-pixel to encode into.
 * @note Only the low @p bpp bits of each byte in @p src will be preserved.
 * @note @p bpp can be in range 1-4. Values outside that range unsupported.
 * @returns True if success, False if invalid/unsupported value of @p bpp.
 */
bool cryptx_bpp_encode(void *dest, const void *src, size_t outlen, uint8_t bpp);

/*******************************************************************
 * @brief Decodes a @p bpp bit encoded byte stream into an octet-encoded byte stream.
 * @param dest Pointer to output octet-encoded data stream.
 * @param src Pointer to input data stream of @b bpp -encoded data.
 * @param len Length of encoded (@p src) data stream. (8 / @p bpp the size of dest)
 * @param bpp Number of bits-per-pixel to decode from.
 * @note @p bpp can be in range 1-4. Values outside that range unsupported.
 * @returns True if success, False if invalid/unsupported value of @p bpp.
 */
bool cryptx_bpp_decode(void *dest, const void *src, size_t inlen, uint8_t bpp);

#endif
