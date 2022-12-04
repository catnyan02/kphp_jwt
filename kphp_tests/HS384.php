@ok
<?php
include "JWT.php";
require_once 'kphp_tester_include.php';

$key = 'a6W2fWlKEXZEyREMx9COX-feY4EFtXlJjYr53l_H53YSA-Gj-DbPBoU5zZmEIy8GRFNRC4CLRk0rNWZ8dDXCsbPiPPz2tE9ZUAPsCQCXln3dYpohVSZiH0HaZ80vxcW1O5oVnmrWes3h_dSWUIZFSc0VJn625VM8MWpkyXV2u3L-ZlCS2PEakRKdskA-Mf2t58RFgdF7HThzWUq2ylFceosVU1xp7VhHesZYFqKMnvQZbFHO48fl0MNdINFzxIfbNkCxloZx0N_Z41ONcvExsz8yJU9yRWCaHSvl0ki9ZkvoVvEx5mEH8m-Xy_SamoSXOdRkdYYnpUgnOMQKKt4qPw';

$payload = [
    'iss' => 'example.org',
    'aud' => 'example.com',
    'iat' => 1356999524,
    'nbf' => 1357000000
];

$jwt = nyan02\kphp_jwt\JWT::encode($payload, $key, 'HS384');
$decoded = nyan02\kphp_jwt\JWT::decode($jwt, $key, 'HS384');
var_dump($decoded);

