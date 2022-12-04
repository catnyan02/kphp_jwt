@ok
<?php
include "JWT.php";
require_once 'kphp_tester_include.php';

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

$jwt = nyan02\kphp_jwt\JWT::encode($payload, $privateKey, 'ES384');
$decoded = nyan02\kphp_jwt\JWT::decode($jwt, $publicKey, 'ES384');
var_dump($decoded);

