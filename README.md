# jwkaas
Python JSON Web Key Advanced Acquiring Store

## Introduction to JWT, JWS and JWK
This Python module provides JSON Web Token decoding and verification. The validity of a JWT is based on theJSON Web Signature (JWS). A signature is verified using the corresponding JSON Web Key (JWK). Many identify providers publish the JSON Web Keys to verify their signatures as a JSON document on the Internet (these are referred to as the JWKS).
A JWT may contain several claims (see [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4)). jwkaas will check the _exp_ and _nbf_ claim based on the current time. The _aud_ and _iss_ claim will be verified based on whether this information was specified on initialization (see _Usage_ below)

## Introduction to jwkaas
The Python module jwkaas provides the functionality to verify a JWT and decode it to get the information from the JWT. It includes acquiring and storing the JWKS required to verify the signatures.

## Usage
The functionality is provided by the JWKaas class. On initialization the expected audience and issuer must specified. A JWT will only be accepted if the values match the corresponding token claims _aud_ and _iss_. The JWKS can be specified by an url from where the JWKS json can be downloaded, and/or by a file containing the JWKS json. If both sources contain a key with the same key id (kid), the key from the url will precede the key from the file.
Example initialisation:
```
my_jwkaas = JWKaas('https://my.audience'", 
                   'https://my.iam.server/issueing/the/token',
                   jwks_url='https://my.iam.server/well-known/keys.jwks')
```

Verifying and decoding a JWT is done by the JWKaas.get_token_info, like this:
```
token_info = my_jwkaas.get_token_info(token)
if token_info is not None:
    logging.info("Token info: %s", token_info)
else:
    logging.info("Token is invalid")
```

## Using jwkaas with Connexion OpenAPI First framework for Python
JWKaas also provides JWKaas.get_connexion_token_info. This returns the token_info extended with the _scope_ key as used by [Connexion](https://github.com/zalando/connexion). The value of _scope_ will be copied from the _scp_ claim, which is the claim used by Azure AD to specify the scopes. Other IAM servers might use yet another claim to specify the scopes, those are currently not implemented.

## Acknowledgements
jwkaas is build around [PyJWT](https://github.com/jpadilla/pyjwt), a Python implementation of [RFC 7519](https://tools.ietf.org/html/rfc7519).
