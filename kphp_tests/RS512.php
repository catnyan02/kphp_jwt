@ok
<?php
require_once 'kphp_tester_include.php';
include "JWT.php";

$privateKey = '-----BEGIN RSA PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDL1pAmRsZcjGnb
NhickIJphZiyVWDw+1gpvj/WRibLQ6ikXHsK/pY84eQDhUQtYdkVy/nKEIPjF8lj
Hp6tqTtc6JX2SvMll4RO2lCw3IKVx9gJwh7yIJz6YXKUNfSCLBZLF3MkFMOZps/q
p1ykbu2Qvr3j4D/ytW40TT8AfTEfNOEJOFR8El5tL5QLAsFTaACjokBSYH91w7At
qKO3YRCUtT4cwg9sgx+3XXdEuoB/yHBAuU9//Ec2Ff5dsV2tO+hBMPmIyey0ExHS
wS86Z5y4QufsebhJ1L6GoxX7qbO0MWJADVcZb2odtVW05xA+uH8DZUK7LIGVPkyo
nRmRYPLNAgMBAAECggEAFHJrd0t2LmZvX+vnQB1G16rtDEaAOOwdheJtqOLUlWMu
EX6tYQb0rxrBspC1rA+6pPMXFWvervL94pF5vVXSfJlgIZqXFVhDj11a5sLX3opz
Y1czn3oiBQOtaKyY4E3n1pR9mkry7ADNrm4nXt85uWFIzwj5oTEN4vU0sqncOZL4
eNHcxbg7RhsC8rP9wrr7H6D/twn3/RjZ21Ivys8taveVqFR+XAq1ouVklLN1QdVy
59htoFyCtSvWHy0hDgQDL1mzFs0Q1WYqk2utPLUntPNZ79tfrDyKawjaIzDy7MnM
dVpP/djL5qPX/FtTi61PALBsHuY0SmT+eVQoamsTAQKBgQDucQgHFxZ334UOup9A
mEdaVYVewH70blFSpefwgc9bw8oi+e8SviDxYCSqDMsWkbJCZJL6gQarikS3sT+X
+BNkmIg2kaa9hfLHdRPs5mbusM36iBzhTnWuMDhIpe93gXPUVmqqdZF7A2G2qrPb
nTQ71bvMCmJq7brH5zB9N9z34QKBgQDa2TUlnN1U+k0ZOWByhzqXGCKrhJNPGIxX
SwCtGHswfOwEKfvFSSwknulhvKVFbkD8WqguzX+m+f2KeErSb5FMJ0MHo2hbtf4F
7FkK3FwZCSEDYsED24JRspSoQtZsktHBWSIdpDnEcfRYtD6Uiw2e7JMUbeApKsYT
CNFmlphobQKBgQCSbug3Mn6h76uPeB0FVn+7gnn9zsoo4vcegrUGhzIJcRxajpO8
NveURS8/H8w5eBC5pXp+TW8DOk8pYLllYvzF8sb0fE6iZfjLdaNfAcCFJh/ZlG3o
EH9FEmf+damzAtVXuhqXxMwrd9AylnMOlGTXulMy4829TXJAAkNNI1mZAQKBgGRM
sELwxa+wl6070qwqtfuRoDIjrK/PfGJ1iXXLhooOdszhwPYGNykBe8zDfKt5gGcn
1XS90gdhA4Z24zPW1iykwd+6UJXXrvhf/d8wZzVCLdMza2qtK+jtg5wqJcPU9jU6
+JvFLISQBYCx+wxxPmjb2/y87sNvSyBmJjJySp9xAoGBAL55o9jHuCYvVvnsiCHL
Qh37GODlX2SHgY8ycvycrOx4LungBDYAno97QcVdjRxzanFaIBNvfSjA9D2QXYFY
Vn5o554D6FXSXxrpnR8mDe1vKHDw45e1r82luJIGJdkqer4GnpiDNY2y7Yt1HcsX
J18tFKN049UmyGOM1PSVvA7h
-----END RSA PRIVATE KEY-----';

$publicKey = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy9aQJkbGXIxp2zYYnJCC
aYWYslVg8PtYKb4/1kYmy0OopFx7Cv6WPOHkA4VELWHZFcv5yhCD4xfJYx6erak7
XOiV9krzJZeETtpQsNyClcfYCcIe8iCc+mFylDX0giwWSxdzJBTDmabP6qdcpG7t
kL694+A/8rVuNE0/AH0xHzThCThUfBJebS+UCwLBU2gAo6JAUmB/dcOwLaijt2EQ
lLU+HMIPbIMft113RLqAf8hwQLlPf/xHNhX+XbFdrTvoQTD5iMnstBMR0sEvOmec
uELn7Hm4SdS+hqMV+6mztDFiQA1XGW9qHbVVtOcQPrh/A2VCuyyBlT5MqJ0ZkWDy
zQIDAQAB
-----END PUBLIC KEY-----';

$payload = [
    'iss' => 'example.org',
    'aud' => 'example.com',
    'iat' => 1356999524,
    'nbf' => 1357000000
];

$jwt = nyan02\kphp_jwt\JWT::encode($payload, $privateKey, 'RS512');
$decoded = nyan02\kphp_jwt\JWT::decode($jwt, $publicKey, 'RS512');
var_dump($decoded);

