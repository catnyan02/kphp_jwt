<?php

namespace KPHP\JWT;

use ArrayObject;
use DomainException;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use stdClass;
use TypeError;
use UnexpectedValueException;


class JWTTest extends TestCase
{
    public function testUrlSafeCharacters()
    {
        $encoded = JWT::encode(['message' => 'f?'], 'a', 'HS256');
        $expected = array('message' => 'f?');
        $this->assertEquals((array) $expected, JWT::decode($encoded,'a', 'HS256'));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->expectException(\DomainException::class);
        JWT::encode(['message' => pack('c', 128)], 'a', 'HS256');
    }

    public function testMalformedJsonThrowsException()
    {
        $this->expectException(DomainException::class);
        JWT::jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken()
    {
        $this->expectException(\UnexpectedValueException::class);
        $payload = [
            'message' => 'abc',
            'exp' => time() - 20, // time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, 'my_key', 'HS256');
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->expectException(\UnexpectedValueException::class);
        $payload = [
            'message' => 'abc',
            'nbf' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, 'my_key', 'HS256');
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->expectException(\UnexpectedValueException::class);
        $payload = [
            'message' => 'abc',
            'iat' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, 'my_key', 'HS256');
    }

    public function testValidToken()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, 'my_key', 'HS256');
        $this->assertEquals($decoded['message'], 'abc');
    }

    public function testValidTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'exp' => time() - 20, // time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, 'my_key', 'HS256');
        $this->assertEquals($decoded['message'], 'abc');
        JWT::$leeway = 0;
    }

    public function testExpiredTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'exp' => time() - 70, // time far in the past
        ];
        $this->expectException(\UnexpectedValueException::class);
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, 'my_key', 'HS256');
        $this->assertEquals($decoded['message'], 'abc');
        JWT::$leeway = 0;
    }

    public function testValidTokenWithNbf()
    {
        $payload = [
            'message' => 'abc',
            'iat' => time(),
            'exp' => time() + 20, // time in the future
            'nbf' => time() - 20
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, 'my_key', 'HS256');
        $this->assertEquals($decoded['message'], 'abc');
    }

    public function testValidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'nbf' => time() + 20, // not before in near (leeway) future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, 'my_key', 'HS256');
        $this->assertEquals($decoded['message'], 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'nbf' => time() + 65,  // not before too far in future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(\UnexpectedValueException::class);
        JWT::decode($encoded, 'my_key', 'HS256');
        JWT::$leeway = 0;
    }

    public function testValidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'iat' => time() + 20, // issued in near (leeway) future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, 'my_key', 'HS256');
        $this->assertEquals($decoded['message'], 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'iat' => time() + 65, // issued too far in future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(\UnexpectedValueException::class);
        JWT::decode($encoded, 'my_key', 'HS256');
        JWT::$leeway = 0;
    }

    public function testInvalidToken()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(\UnexpectedValueException::class);
        JWT::decode($encoded, 'my_key2', 'HS256');
    }

    public function testNullKeyFails()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(TypeError::class);
        JWT::decode($encoded, null, 'HS256');
    }

    public function testEmptyKeyFails()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(InvalidArgumentException::class);
        JWT::decode($encoded, '', 'HS256');
    }

    public function testNoneAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, 'my_key', 'none');
    }

    public function testIncorrectAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, 'my_key', 'RS256');
    }

    public function testEmptyAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, 'my_key', '');
    }

    public function testAdditionalHeaders()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256', null, ['cty' => 'test-eit;v=1']);
        $expected = array('message' => 'abc');
        $this->assertEquals(JWT::decode($msg, 'my_key', 'HS256'), $expected);
    }

    public function testInvalidSegmentCount()
    {
        $this->expectException(UnexpectedValueException::class);
        JWT::decode('brokenheader.brokenbody', 'my_key', 'HS256');
    }

    public function testInvalidSignatureEncoding()
    {
        $msg = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6ImZvbyJ9.Q4Kee9E8o0Xfo4ADXvYA8t7dN_X_bU9K5w6tXuiSjlUxx';
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, 'secret', 'HS256');
    }

    public function testHSEncodeDecode()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $expected = array('message' => 'abc');
        $this->assertEquals(JWT::decode($msg, 'my_key', 'HS256'), $expected);
    }

    public function testRSEncodeDecode()
    {
        $privKey = '-----BEGIN RSA PRIVATE KEY-----
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

        $pubKey = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pSjbSYZVebtTRBLxBz5H
4i2p/llLCrEeQhta5kaQu/RnvuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t
0tyazyZ8JXw+KgXTxldMPEL95+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4
ehde/zUxo6UvS7UrBQIDAQAB
-----END PUBLIC KEY-----';

        $msg = JWT::encode(['message' => 'abc'], $privKey, 'RS256');
        $decoded = JWT::decode($msg, $pubKey, 'RS256');
        $expected = array('message' => 'abc');
        $this->assertEquals($decoded, $expected);
    }

    public function testDecodesEmptyArrayAsObject()
    {
        $key = 'yma6Hq4XQegCVND8ef23OYgxSrC3IKqk';
        $payload = [];
        $jwt = JWT::encode($payload, $key, 'HS256');
        $decoded = JWT::decode($jwt, $key, 'HS256');
        $this->assertEquals($payload, $decoded);
    }

    public function testDecodesArraysInJWTAsArray()
    {
        $key = 'yma6Hq4XQegCVND8ef23OYgxSrC3IKqk';
        $payload = ['foo' => [1, 2, 3]];
        $jwt = JWT::encode($payload, $key, 'HS256');
        $decoded = JWT::decode($jwt, $key, 'HS256');
        $this->assertEquals($payload['foo'], $decoded['foo']);
    }
    public function testESEncodeDecode()
    {
        $privKey = '-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBQJuwafREZ1494Fm2MTVXuZbWXVAOwIAxGhyLdc3CChzi0FVXZq8e6
65oR0Qq9Jv2gBwYFK4EEACKhZANiAAQWFddzIqZaROR1VtZhhTd20mqknQmYsZ+0
R03NQQUQpJTkyWcuv8WNyd6zO9cCoQEzi94kX907/OEWTjhuH8QtdunT+ef1BpWJ
W1Cm5O+m7b155/Ho99QypfQr74hLg1A=
-----END EC PRIVATE KEY-----';

        $pubKey = '-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFhXXcyKmWkTkdVbWYYU3dtJqpJ0JmLGf
tEdNzUEFEKSU5MlnLr/FjcneszvXAqEBM4veJF/dO/zhFk44bh/ELXbp0/nn9QaV
iVtQpuTvpu29eefx6PfUMqX0K++IS4NQ
-----END PUBLIC KEY-----';

        $msg = JWT::encode(['message' => 'abc'], $privKey, 'ES384');
        $decoded = JWT::decode($msg, $pubKey, 'ES384');
        $expected = array('message' => 'abc');
        $this->assertEquals($decoded, $expected);
    }
}
