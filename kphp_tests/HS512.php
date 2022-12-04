@ok
<?php
require_once 'kphp_tester_include.php';
include "JWT.php";

$key = 'kttt6rpXVBQAxkAl-fhUMZDJTlHu6Mg0EXEZATJ9GSG4rd2Dpbb-5Wpt5j1mqfeB0pr4hUxM00ceBc4MEwanI4VlsdEScY-vbpkb4L_unuOmedGCb6eI32pchOrmS5NwNmdEKNuZy9d_cuwXSyHYhXyHqqadU3edGO-q-vjLCnJwlhT_i4zC9RkVf9lv-IRqCdPNLRjdD4DUZ_NXdV0VEqMRuLr1c-Sjpjh84lknZDZ5xCSJYqEtxaXlb2z0kYcyjt2Kb5n2n4GIBu6U6hb2qqvnqkUAlcUBLFZcQ8XVUYjDSoDE6f33pG1D2QbqLP22ToDvvIt04jZs5lDM6qQHrQ';

$payload = [
    'iss' => 'example.org',
    'aud' => 'example.com',
    'iat' => 1356999524,
    'nbf' => 1357000000
];

$jwt = nyan02\kphp_jwt\JWT::encode($payload, $key, 'HS512');
$decoded = nyan02\kphp_jwt\JWT::decode($jwt, $key, 'HS512');
var_dump($decoded);

