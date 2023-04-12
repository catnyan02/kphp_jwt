# kphp_jwt

## Intro
A simple library to encode and decode JSON Web Tokens (JWT) in PHP, conforming to RFC 7519.

## Installation
```composer require nyan02/kphp_jwt```

## Available features
Class JWT has property **$supported_algs** that lists supported algorithms.

Using property **$timestamp** it is possible to fix a value within testing. Defaults to PHP time() value if null.

When checking nbf, iat or expiration times, you might want to provide some extra **$leeway** time to account for clock skew by using leeway property.

Available functions:
```
JWT::encode(array $payload, string $key, string $alg, string $keyId = null, $head = null) : string

JWT::decode(string $jwt, string $key, string $alg): array
```

## Simple example with HS256 (hash_hmac)
```
 namespace nyan02\kphp_jwt;
 include 'vendor/autoload.php';

 $key = 'example_key';

 $payload = [
 'iss' => 'example.org',
 'aud' => 'example.com',
 'iat' => 1356999524,
 'nbf' => 1357000000
 ];

 $jwt = JWT::encode($payload, $key, 'HS256');
 echo "Encode:\n" . print_r($jwt, true) . "\n";
 $decoded = JWT::decode($jwt, $key, 'HS256');

 var_dump($decoded);

/**
* You can add a leeway to account for when there is a clock skew times between
* the signing and verifying servers. It is recommended that this leeway should
* not be bigger than a few minutes.
*/
  JWT::$leeway = 60; // $leeway in seconds
  $decoded = JWT::decode($jwt, $key, 'HS256');
```

## Example with RS256 (openssl)
```
 namespace nyan02\kphp_jwt;
 include 'vendor/autoload.php';

 $privateKey = '-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8kGa1pSjbSYZVebtTRBLxBz5H4i2p/llLCrEeQhta5kaQu/Rn
vuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t0tyazyZ8JXw+KgXTxldMPEL9
5+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4ehde/zUxo6UvS7UrBQIDAQAB
AoGAb/MXV46XxCFRxNuB8LyAtmLDgi/xRnTAlMHjSACddwkyKem8//8eZtw9fzxz
bWZ/1/doQOuHBGYZU8aDzzj59FZ78dyzNFoF91hbvZKkg+6wGyd/LrGVEB+Xre0J
Nil0GReM2AHDNZUYRv+HYJPIOrB0CRczLQsgFJ8K6aAD6F0CQQDzbpjYdx10qgK1
cP59UHiHjPZYC0loEsk7s+hUmT3QHerAQJMZWC11Qrn2N+ybwwNblDKv+s5qgMQ5
5tNoQ9IfAkEAxkyffU6ythpg/H0Ixe1I2rd0GbF05biIzO/i77Det3n4YsJVlDck
ZkcvY3SK2iRIL4c9yY6hlIhs+K9wXTtGWwJBAO9Dskl48mO7woPR9uD22jDpNSwe
k90OMepTjzSvlhjbfuPN1IdhqvSJTDychRwn1kIJ7LQZgQ8fVz9OCFZ/6qMCQGOb
qaGwHmUK6xzpUbbacnYrIM6nLSkXgOAwv7XXCojvY614ILTK3iXiLBOxPu5Eu13k
eUz9sHyD6vkgZzjtxXECQAkp4Xerf5TGfQXGXhxIX52yH+N2LtujCdkQZjXAsGdm
B2zNzvrlgRmgBrklMTrMYgm1NPcW+bRLGcwgW2PTvNM=
-----END RSA PRIVATE KEY-----';

 $publicKey = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pSjbSYZVebtTRBLxBz5H
4i2p/llLCrEeQhta5kaQu/RnvuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t
0tyazyZ8JXw+KgXTxldMPEL95+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4
ehde/zUxo6UvS7UrBQIDAQAB
-----END PUBLIC KEY-----';

 $payload = [
 'iss' => 'example.org',
 'aud' => 'example.com',
 'iat' => 1356999524,
 'nbf' => 1357000000
 ];

 $jwt = JWT::encode($payload, $privateKey, 'RS256');
 echo "Encode:\n" . print_r($jwt, true) . "\n";

 $decoded = JWT::decode($jwt, $publicKey, 'RS256');
 var_dump($decoded);
```

## Example with ES384 (openssl)
```
 namespace nyan02\kphp_jwt;
 include 'vendor/autoload.php';

 $privateKey = '-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBQJuwafREZ1494Fm2MTVXuZbWXVAOwIAxGhyLdc3CChzi0FVXZq8e6
65oR0Qq9Jv2gBwYFK4EEACKhZANiAAQWFddzIqZaROR1VtZhhTd20mqknQmYsZ+0
R03NQQUQpJTkyWcuv8WNyd6zO9cCoQEzi94kX907/OEWTjhuH8QtdunT+ef1BpWJ
W1Cm5O+m7b155/Ho99QypfQr74hLg1A=
-----END EC PRIVATE KEY-----';

 $publicKey = '-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFhXXcyKmWkTkdVbWYYU3dtJqpJ0JmLGf
tEdNzUEFEKSU5MlnLr/FjcneszvXAqEBM4veJF/dO/zhFk44bh/ELXbp0/nn9QaV
iVtQpuTvpu29eefx6PfUMqX0K++IS4NQ
-----END PUBLIC KEY-----';

 $payload = [
 'iss' => 'example.org',
 'aud' => 'example.com',
 'iat' => 1356999524,
 'nbf' => 1357000000
 ];

 $jwt = JWT::encode($payload, $privateKey, 'ES384');
 echo "Encode:\n" . print_r($jwt, true) . "\n";

 $decoded = JWT::decode($jwt, $publicKey, 'ES384');
 var_dump($decoded);
```

## Compiling examples
Install KPHP from the Docker registry by executing the following command:

``` docker pull vkcom/kphp ```

Run the container vkcom/kphp:

```docker run -ti -v ~/[Your_Directory]/:/tmp/dev:rw -p 8080:8080 vkcom/kphp```

Then just compile my.php and run the server — inside Docker:

```
kphp /tmp/dev/[Your_File_Name].php

./kphp_out/server -H 8080 -f 1
```

For more information see https://vkcom.github.io/kphp/kphp-basics/compile-sample-script.html