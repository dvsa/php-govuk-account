<?php

namespace Dvsa\GovUkAccount\Helper;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;

class DidDocumentParser
{
    /**
     * This method parses a DID document from a JSON string into an array.
     *
     * @param string $didDocument The DID document as a JSON string
     * @return array
     */
    public static function parse(string $didDocument): array
    {
        $didDocument = json_decode($didDocument, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException('Invalid DID document');
        }

        return $didDocument;
    }

    /**
     * This method attempts to extract JWKs from a DID document and parse them into Key objects.
     *
     * @param string|array $didDocument The DID document as a JSON string or an array
     * @return Key[]
     */
    public static function parseToKeyArray(string|array $didDocument): array
    {
        if (is_string($didDocument)) {
            $didDocument = self::parse($didDocument);
        }

        $keys = [];

        if (!isset($didDocument['assertionMethod'])) {
            throw new \InvalidArgumentException('DID document has no assertion method');
        }

        foreach ($didDocument['assertionMethod'] as $key) {
            if (($key['type'] ?? null) !== 'JsonWebKey') {
                continue;
            }
            if (($key['publicKeyJwk']['alg'] ?? null) == null) {
                continue;
            }

            // Inject 'kid' into the JWK if not present
            if (!isset($key['publicKeyJwk']['kid'])) {
                $key['publicKeyJwk']['kid'] = $key['id'];
            }

            $parsedKey = JWK::parseKey($key['publicKeyJwk'], $key['publicKeyJwk']['alg']);
            if ($parsedKey === null) {
                continue;
            }

            $keys[$key['id']] = $parsedKey;
        }

        if (empty($keys)) {
            throw new \InvalidArgumentException('No valid keys found in DID document');
        }

        return $keys;
    }
}
