@ok
<?php
include "JWT.php";
require_once 'kphp_tester_include.php';

$privateKey = '-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIOgg3e3PLplzpqHuxCueks+Uj59a2Z1RFzYSq4/2qOrqoAcGBSuBBAAK
oUQDQgAEcsGDve0tmbRng/wfTEjnH45FvZ19e6yT3bRMcZviBP/6PeyeGBJWIUOb
8H/P/OofpHtY2RcR13cCubFGSgbKSw==
-----END EC PRIVATE KEY-----';

$publicKey = '-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEcsGDve0tmbRng/wfTEjnH45FvZ19e6yT
3bRMcZviBP/6PeyeGBJWIUOb8H/P/OofpHtY2RcR13cCubFGSgbKSw==
-----END PUBLIC KEY-----';

$payload = [
    'iss' => 'example.org',
    'aud' => 'example.com',
    'iat' => 1356999524,
    'nbf' => 1357000000
];

$jwt = nyan02\kphp_jwt\JWT::encode($payload, $privateKey, 'ES256');
$decoded = nyan02\kphp_jwt\JWT::decode($jwt, $publicKey, 'ES256');
var_dump($decoded);

