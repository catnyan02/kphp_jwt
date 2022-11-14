# kphp_jwt



## Getting started

[78][2022-11-14 12:08:52.482323 php-runner.cpp  328] Critical error during script execution: [1668416932] [78] Error 0: OpenSSL unable to sign data.
Unhandled DomainException caught in file JWT_nyah.php at line 264.

$success = \openssl_sign($msg, $signature, $key, $algorithm);
при key - string не работает 

![img.png](img.png)