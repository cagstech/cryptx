#!/bin/sh

mkdir -p .test_keys
echo "\ngenerating RSA and EC keys for testing...\n"

# generate RSA
openssl genrsa -out .test_keys/rsa_private.pem 1024
openssl rsa -in .test_keys/rsa_pair.pem -pubout -out .test_keys/rsa_public.pem
echo "\nRSA\n"
echo "rsa_private:\n"
cat .test_keys/rsa_private.pem
echo "rsa_public:\n"
cat .test_keys/rsa_public.pem

# generate EC
openssl ecparam -name sect233k1 -genkey -noout -out .test_keys/ec_tmp.pem
openssl pkcs8 -topk8 -nocrypt -in .test_keys/ec_tmp.pem -out .test_keys/ec_private.pem
openssl ec -in .test_keys/ec_private.pem -pubout -out .test_keys/ec_public.pem
echo "\nec_private\n"
cat .test_keys/ec_private.pem
echo "\nec_public\n"
cat .test_keys/ec_public.pem

