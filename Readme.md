API to demonstrate various spring boot rest features

Reference
https://bitbucket.org/b_c/jose4j/wiki/JWT%20Examples
https://adangel.org/2016/08/29/openssl-rsa-java/


# Generate Key Pair
openssl genrsa -des3 -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
openssl pkcs8 -in private.pem -topk8 -nocrypt -out private-pkcs8.pem