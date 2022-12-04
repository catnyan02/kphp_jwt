@ok
<?php
include "JWT.php";
require_once 'kphp_tester_include.php';

$key = 'DygNDna_93ognL6pAgnQcLAsr5aGObvjgvumGw32UEgdh1re418pfLj2vFLPr3ODdEPB-SMOXVFOPDbubZ470L3Q0P-V8TiSHMtMHyxI2Zb25gjm-EysI7btdQLTDJqbd9d_LJ7373gaBsLt7LOwt0shN6yzLbkHYvl86aMsaLur1Nk6MkmzC3JrMattTnO_KdIZmBNYZ1bemKsClarWgfBKpd-145e5JqWpRjwa--OG4_JDRENoom7lWW0UnvAKKrG2LyJ1ip30kIiWqgC8tMx7lpnMA6schlXi_y-oQL37qT7RjTmyRD2mvovO5AIhzNslfjW-fH1bec4OctlknQ';

$payload = [
    'iss' => 'example.org',
    'aud' => 'example.com',
    'iat' => 1356999524,
    'nbf' => 1357000000
];

$jwt = nyan02\kphp_jwt\JWT::encode($payload, $key, 'HS256');
$decoded = nyan02\kphp_jwt\JWT::decode($jwt, $key, 'HS256');
var_dump($decoded);

