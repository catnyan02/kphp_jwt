<?php

namespace Nyan\Kphp_jwt\JWT;
require_once '../vendor/autoload.php';

class JWT
{
    public static array $supported_algs = [
        'ES384' => ['openssl', OPENSSL_ALGO_SHA384],
        'ES256' => ['openssl', OPENSSL_ALGO_SHA256],
        'HS256' => ['hash_hmac', 'sha256'],
        'HS384' => ['hash_hmac', 'sha384'],
        'HS512' => ['hash_hmac', 'sha512'],
        'RS256' => ['openssl', OPENSSL_ALGO_SHA256],
        'RS384' => ['openssl', OPENSSL_ALGO_SHA384],
        'RS512' => ['openssl', OPENSSL_ALGO_SHA512],
    ];

    public static ?int $timestamp = null;
    public static int $leeway = 0;

    /**
     * Converts and signs a PHP array into a JWT string.
     *
     * @param array<mixed>          $payload PHP array
     * @param string $key The secret key.
     * @param string                $alg     Supported algorithms are 'ES384','ES256', 'HS256', 'HS384',
     *                                       'HS512', 'RS256', 'RS384', and 'RS512'
     * @param ?string                $keyId
     * @param ?array                 $head An array with header elements to attach
     *
     * @return string A signed JWT

     */

    # TODO: $key types resource|OpenSSLAsymmetricKey|OpenSSLCertificate for $key NEED DUCK TYPING
    # TODO: try libsodium

    public static function encode(
        array $payload,
              $key,
        string $alg,
        string $keyId = null,
        $head = null
    ): string {
        $header = ['typ' => 'JWT', 'alg' => $alg];
        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }
        if (isset($head) && \is_array($head)) {
            $header = \array_merge($head, $header);
        }
        $segments = [];
        $segments[] = static::urlsafeB64Encode((string) static::jsonEncode($header));
        $segments[] = static::urlsafeB64Encode((string) static::jsonEncode($payload));
        $signing_input = \implode('.', $segments);

        $signature = static::sign($signing_input, $key, $alg);
        $segments[] = static::urlsafeB64Encode($signature);

        return \implode('.', $segments);
    }

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string                 $jwt            The JWT
     * @param string                 $key     If the algorithm used is asymmetric, this is the public key
     * @param string                 $alg     Supported algorithms are 'ES384','ES256', 'HS256', 'HS384',
     *                                        'HS512', 'RS256', 'RS384', and 'RS512'
     *
     *
     *
     * @return mixed The JWT's payload as a PHP object
     *
     * @throws \InvalidArgumentException     Provided key/key-array was empty or malformed
     * @throws \DomainException              Provided JWT is malformed
     * @throws \UnexpectedValueException     Provided JWT was invalid
     * @throws \SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     * @throws \BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
     * @throws \BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
     * @throws \ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
     *
     * @uses jsonDecode
     * @uses urlsafeB64Decode
     */
    public static function decode(
        string $jwt,
        string $key,
        string $alg

    ): array {
        // Validate JWT
        $timestamp = \is_null(static::$timestamp) ? \time() : static::$timestamp;

        if (empty($key)) {
            throw new \InvalidArgumentException('Key may be empty');
        }
        $tks = \explode('.', $jwt);
        if (\count($tks) !== 3) {
            throw new \UnexpectedValueException('Wrong number of segments');
        }
        list($headb64, $bodyb64, $cryptob64) = $tks;
        $headerRaw = static::urlsafeB64Decode($headb64);
        if (null === ($header = static::jsonDecode($headerRaw))) {
            throw new \UnexpectedValueException('Invalid header encoding');
        }
        $payloadRaw = static::urlsafeB64Decode($bodyb64);
        if (null === ($payload = static::jsonDecode($payloadRaw))) {
            throw new \UnexpectedValueException('Invalid claims encoding');
        }
        $sig = static::urlsafeB64Decode($cryptob64);
        if (empty($header['alg'])) {
            throw new \UnexpectedValueException('Empty algorithm');
        }
        if (empty(static::$supported_algs[$header['alg']])) {
            throw new \UnexpectedValueException('Algorithm not supported');
        }

        if (!self::constantTimeEquals($alg, (string) $header['alg'])) {
            throw new \UnexpectedValueException('Incorrect algorithm');
        }
        if ($header['alg'] === 'ES256' || $header['alg'] === 'ES384') {
            // OpenSSL expects an ASN.1 DER sequence for ES256/ES384 signatures
            $sig = self::signatureToDER($sig);
        }
        if (!self::verify("{$headb64}.{$bodyb64}", $sig, $key, (string) $header['alg'])) {
            throw new \UnexpectedValueException('Signature verification failed');
        }

        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($payload['nbf']) && $payload['nbf'] > ($timestamp + static::$leeway)) {
            throw new \UnexpectedValueException(
                'Cannot handle token prior to ' . \date(\DateTime::ISO8601, $payload['nbf'])
            );
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (isset($payload['iat']) && $payload['iat'] > ($timestamp + static::$leeway)) {
            throw new \UnexpectedValueException(
                'Cannot handle token prior to ' . \date(\DateTime::ISO8601, $payload['iat'])
            );
        }

        // Check if this token has expired.
        if (isset($payload['exp']) && ($timestamp - static::$leeway) >= $payload['exp']) {
            throw new \UnexpectedValueException('Expired token');
        }

        return $payload;
    }

    /**
     * Encode a string with URL-safe Base64.
     *
     * @param string $input The string you want encoded
     *
     * @return string The base64 encode of what you passed in
     */
    public static function urlsafeB64Encode(string $input): string
    {
        return \str_replace('=', '', \strtr(\base64_encode($input), '+/', '-_'));
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     *
     * @throws \InvalidArgumentException invalid base64 characters
     */
    public static function urlsafeB64Decode(string $input): string
    {
        $remainder = \strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= \str_repeat('=', $padlen);
        }
        $input = \strtr($input, '-_', '+/');
        if (false === ($result = \base64_decode($input))) {
            throw new \InvalidArgumentException('Unable to decode B64');
        }
        return (string) $result;
    }

    /**
     * Encode a PHP array into a JSON string.
     *
     * @param ?array $input A PHP array
     *
     * @return string JSON representation of the PHP array
     *
     * @throws \DomainException Provided object could not be encoded to valid JSON
     */
    public static function jsonEncode(array $input): string
    {
        // TO DO: kphp json encode decode
        $json = \json_encode($input);
        # $json = \json_encode($input, \JSON_UNESCAPED_SLASHES);
        # TODO: Check php-json module in KPHP or why json_encode works like PHP <= 5.3
        if ($json === 'null' && $input !== null) {
            throw new \DomainException('Null result with non-null input');
        }
        if ($json === false) {
            throw new \DomainException('Provided object could not be encoded to valid JSON');
        }
        return $json;
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     *
     * @return mixed The decoded JSON string
     *
     * @throws \DomainException Provided string was invalid JSON
     */
    public static function jsonDecode(string $input)
    {
        $arr = \json_decode($input, true);

        if ($arr === null && $input !== 'null') {
            throw new \DomainException('Null result with non-null input');
        }
        return $arr;
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string $msg  The message to sign
     * @param string $key  The secret key.
     * @param string $alg  Supported algorithms are 'ES384','ES256', 'HS256', 'HS384',
     *                    'HS512', 'RS256', 'RS384', and 'RS512'
     *
     * @return string An encrypted message
     *
     * @throws \DomainException Unsupported algorithm or bad key was specified
     */
    public static function sign(
        string $msg,
               $key,
        string $alg
    ): string {
        if (empty(static::$supported_algs[$alg])) {
            throw new \DomainException('Algorithm not supported');
        }
        list($function, $algorithm) = static::$supported_algs[$alg];
        switch ($function) {
            case 'hash_hmac':
                if (!\is_string($key)) {
                    throw new \InvalidArgumentException('key must be a string when using hmac');
                }
                return \hash_hmac($algorithm, $msg, $key, true);
            case 'openssl':
                $signature = '';
                $success = \openssl_sign($msg, $signature, $key, $algorithm);
                if (!$success) {
                    throw new \DomainException('OpenSSL unable to sign data');
                }
                if ($alg === 'ES256') {
                    $signature = self::signatureFromDER($signature, 256);
                } elseif ($alg === 'ES384') {
                    $signature = self::signatureFromDER($signature, 384);
                }
                return $signature;
        }

        throw new \DomainException('Algorithm not supported');
    }

    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string $msg         The original message (header and body)
     * @param string $signature   The original signature
     * @param string $keyMaterial For HS*, a string key works. for RS*, must be an instance of OpenSSLAsymmetricKey
     * @param string $alg         The algorithm
     *
     * @return bool
     *
     * @throws \DomainException Invalid Algorithm, bad key, or OpenSSL failure
     */
    private static function verify(
        string $msg,
        string $signature,
               $keyMaterial,
        string $alg
    ): bool {
        if (empty(static::$supported_algs[$alg])) {
            throw new \DomainException('Algorithm not supported');
        }

        list($function, $algorithm) = static::$supported_algs[$alg];
        switch ($function) {
            case 'openssl':
                $success = \openssl_verify($msg, $signature, $keyMaterial, $algorithm);
                if ($success === 1) {
                    return true;
                }
                if ($success === 0) {
                    return false;
                }
                // returns 1 on success, 0 on failure, -1 on error.
                throw new \DomainException(
                    'OpenSSL error.'
                );
            case 'hash_hmac':
                $hash = \hash_hmac($algorithm, $msg, $keyMaterial, true);
                return self::constantTimeEquals($hash, $signature);
        }
        throw new \DomainException('Algorithm not supported');
    }

    /**
     * Encodes signature from a DER object.
     *
     * @param   string  $der binary signature in DER format
     * @param   int     $keySize the number of bits in the key
     *
     * @return  string  the signature
     */
    private static function signatureFromDER(string $der, int $keySize): string
    {
        // OpenSSL returns the ECDSA signatures as a binary ASN.1 DER SEQUENCE
        list($offset, $_) = self::readDER($der);
        list($offset, $r) = self::readDER($der, $offset);
        list($offset, $s) = self::readDER($der, $offset);

        // Convert r-value and s-value from signed two's compliment to unsigned
        // big-endian integers
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");

        // Pad out r and s so that they are $keySize bits long
        $r = \str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
        $s = \str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * Reads binary DER-encoded data and decodes into a single object
     *
     * @param string $der the binary data in DER format
     * @param int $offset the offset of the data stream containing the object
     * to decode
     *
     * @return tuple<int, string|null> the new offset and the decoded object
     */
    private static function readDER(string $der, int $offset = 0): array
        # TODO: no array return
    {
        $pos = $offset;
        $size = \strlen($der);
        $constructed = (\ord($der[$pos]) >> 5) & 0x01;
        $type = \ord($der[$pos++]) & 0x1f;

        // Length
        $len = \ord($der[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x1f;
            $len = 0;
            while ($n-- && $pos < $size) {
                $len = ($len << 8) | \ord($der[$pos++]);
            }
        }

        // Value
        if ($type === 0x03) {
            $pos++; // Skip the first contents octet (padding indicator)
            $data = (string) \substr($der, $pos, $len - 1);
            $pos += $len - 1;
        } elseif (!$constructed) {
            $data = (string) \substr($der, $pos, $len);
            $pos += $len;
        } else {
            $data = null;
        }

        return \tuple($pos, $data);
    }

    /**
     * Convert an ECDSA signature to an ASN.1 DER sequence
     *
     * @param   string $sig The ECDSA signature to convert
     * @return  string The encoded DER object
     */
    private static function signatureToDER(string $sig): string
    {
        // Separate the signature into r-value and s-value
        $length = max(1, (int) (\strlen($sig) / 2));
        list($r, $s) = \str_split($sig, $length);

        // Trim leading zeros
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");

        // Convert r-value and s-value from unsigned big-endian integers to
        // signed two's complement
        if (\ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (\ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        return self::encodeDER(
            0x10,
            self::encodeDER(0x02, $r) .
            self::encodeDER(0x02, $s)
        );
    }

    /**
     * Encodes a value into a DER object.
     *
     * @param   int     $type DER tag
     * @param   string  $value the value to encode
     *
     * @return  string  the encoded object
     */
    private static function encodeDER(int $type, string $value): string
    {
        $tag_header = 0;
        if ($type === 0x10) {
            $tag_header |= 0x20;
        }

        // Type
        $der = \chr($tag_header | $type);

        // Length
        $der .= \chr(\strlen($value));

        return $der . $value;
    }

    /**
     * @param string $left  The string of known length to compare against
     * @param string $right The user-supplied string
     * @return bool
     */
    public static function constantTimeEquals(string $left, string $right): bool
    {
        if (\function_exists('hash_equals')) {
            return \hash_equals($left, $right);
        }
        $len = \min(self::safeStrlen($left), self::safeStrlen($right));

        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            $status |= (\ord($left[$i]) ^ \ord($right[$i]));
        }
        $status |= (self::safeStrlen($left) ^ self::safeStrlen($right));

        return ($status === 0);
    }

    private static function safeStrlen(string $str): int
    {
        if (\function_exists('mb_strlen')) {
            return \mb_strlen($str, '8bit');
        }
        return \strlen($str);
    }

}
