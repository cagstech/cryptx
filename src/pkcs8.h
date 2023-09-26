
#include <stdint.h>
#include <cryptx.h>

enum _pkcs8_types {
  PKCS_TYPE_PUBLIC,
  PKCS_TYPE_PRIVATE,
  PKCS_TYPE_ENCRYPTED_PRIVATE,
  PKCS_TYPE_UNSET = 0xff
};

enum _pkcs8_algid {
  PKCS_ALG_RSA,
  PKCS_ALG_EC
};

char pkcs_oid[][] = {
  "1.2.840.113549.1.1.1",
  "1.2.840.113549.1.1.1",
};


enum _field_enumeration {
  // universal
  PKCS_OID = 0,
  PKCS_PARAMS = 1,
  PKCS_KEYINFO = 2,
  
  // public key enumerations
  PKCS_PUBKEY_MODULUS = 0,
  PKCS_PUBKEY_EXPONENT = 1,
  
  // private key enumerations
  PKCS_PRIVKEY_VERSION = 0,
  PKCS_PRIVKEY_MODULUS = 1,
  PKCS_PRIVKEY_EXPONENT_PUB = 2,
  PKCS_PRIVKEY_EXPONENT_PRIV = 3,
  PKCS_PRIVKEY_PRIME1 = 4,
  PKCS_PRIVKEY_PRIME2 = 5,
  PKCS_PRIVKEY_EXPONENT1 = 6,
  PKCS_PRIVKEY_EXPONENT2 = 7,
  PKCS_PRIVKEY_COEFF = 8,
  PKCS_PRIVKEY_PRIMEINFO = 9
};

struct _pkcs_field {
  void *data;
  size_t len;
};

struct cryptx_pkcs8_publickey {
  struct _pkcs_field info[2];
  struct publickey { struct _pkcs_field info[2]; };
  uint8_t raw_data[];
};

struct cryptx_pkcs8_privatekey {
  struct _pkcs_field info[2];
  struct privatekey { struct _pkcs_field info[10]; }
  uint8_t raw_data[];
};

typedef enum {
  PKCS_OK,
  PKCS_INVALID_ARG,
  PKCS_INVALID_STRUCT,
  PKCS_INVALID_DATA,
} pkcs_error_t;


