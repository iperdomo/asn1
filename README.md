# asn1 parser

## Resources

* https://lapo.it/asn1js/
* https://blogs.oracle.com/darcy/unsigned-integer-arithmetic-api-now-in-jdk-8
* https://etherhack.co.uk/asymmetric/docs/rsa_key_breakdown.html
* http://cactus.io/resources/toolbox/decimal-binary-octal-hexadecimal-conversion
* https://crypto.stackexchange.com/questions/29115/how-is-oid-2a-86-48-86-f7-0d-parsed-as-1-2-840-113549/29116#29116
* https://www.reddit.com/r/crypto/comments/2hcd4z/converting_a_hexadecimal_private_key_into_a_pem/ckrgs8k/

## Private key generation

### RSA

    openssl genpkey -algorithm RSA -out rsa_private.pem -pkeyopt rsa_keygen_bits:2048

### EC (Elliptic Curve)

    openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem
