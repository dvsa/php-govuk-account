<?php

namespace Helper;

use Dvsa\GovUkAccount\Helper\DidDocumentParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(DidDocumentParser::class)]
class DidDocumentParserTest extends TestCase
{
    public function testParse(): void
    {
        $didDocument = '{"assertionMethod":[{"id":"#key-1","type":"JsonWebKey","publicKeyJwk":{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"x","y":"y"}}]}';
        $parsed = DidDocumentParser::parse($didDocument);

        $this->assertEquals([
            'assertionMethod' => [
                [
                    'id' => '#key-1',
                    'type' => 'JsonWebKey',
                    'publicKeyJwk' => [
                        'alg' => 'ES256',
                        'crv' => 'P-256',
                        'kty' => 'EC',
                        'use' => 'sig',
                        'x' => 'x',
                        'y' => 'y',
                    ],
                ],
            ],
        ], $parsed);
    }

    public function testParseToKeyArray(): void
    {
        $didDocument = '{"assertionMethod":[{"id":"#key-1","type":"JsonWebKey","publicKeyJwk":{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"x","y":"y"}}]}';
        $parsed = DidDocumentParser::parseToKeyArray($didDocument);

        $this->assertCount(1, $parsed);
        $this->assertContainsOnlyInstancesOf(\Firebase\JWT\Key::class, $parsed);
    }

    public function testParseToKeyArrayWithInvalidDocument(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('DID document has no assertion method');

        DidDocumentParser::parseToKeyArray('{"assertionMethodTypo":[]}');
    }

    public function testParseToKeyArrayWithNoValidJsonWebKeyTypes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('No valid keys found in DID document');

        $didDocument = '{"assertionMethod":[{"id":"#key-1","type":"NotJsonWebKey","publicKeyJwk":{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"x","y":"y"}}]}';
        DidDocumentParser::parseToKeyArray($didDocument);
    }

    public function testParseToKeyArrayWithNoAlg(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('No valid keys found in DID document');

        $didDocument = '{"assertionMethod":[{"id":"#key-1","type":"JsonWebKey","publicKeyJwk":{"crv":"P-256","kty":"EC","use":"sig","x":"x","y":"y"}}]}';
        DidDocumentParser::parseToKeyArray($didDocument);
    }

    public function testParseToKeyArrayInvalidKeysAreOmittedButValidOnesRemain(): void
    {
        $didDocument = '{"assertionMethod":[{"id":"#key-1","type":"JsonWebKey","publicKeyJwk":{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"x","y":"y"}},{"id":"#key-2","type":"NotJsonWebKey","publicKeyJwk":{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"x","y":"y"}}]}';
        $parsed = DidDocumentParser::parseToKeyArray($didDocument);

        $this->assertCount(1, $parsed);
        $this->assertContainsOnlyInstancesOf(\Firebase\JWT\Key::class, $parsed);
    }

    public function testParseToKeyArrayMultipleKeysAreParsed(): void
    {
        $didDocument = '{"assertionMethod":[{"id":"#key-1","type":"JsonWebKey","publicKeyJwk":{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"x","y":"y"}},{"id":"#key-2","type":"JsonWebKey","publicKeyJwk":{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"x","y":"y"}}]}';
        $parsed = DidDocumentParser::parseToKeyArray($didDocument);

        $this->assertCount(2, $parsed);
        $this->assertContainsOnlyInstancesOf(\Firebase\JWT\Key::class, $parsed);
    }

    public function testParseToKeyArrayWhereArrayIndexIsKeyIds(): void
    {
        $didDocument = '{"assertionMethod":[{"id":"#key-1","type":"JsonWebKey","publicKeyJwk":{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"x","y":"y"}},{"id":"#key-2","type":"JsonWebKey","publicKeyJwk":{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"x","y":"y"}}]}';
        $parsed = DidDocumentParser::parseToKeyArray($didDocument);

        $this->assertArrayHasKey('#key-1', $parsed);
        $this->assertArrayHasKey('#key-2', $parsed);
    }
}
