<?php

declare(strict_types=1);

namespace Dvsa\GovUkAccount\Helper;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use InvalidArgumentException;

class DidDocumentParser
{
    /**
     * Parse a DID document JSON string into an associative array.
     *
     * @return array<string, mixed>
     *
     * @throws InvalidArgumentException When the input is not valid JSON or
     *                                  does not decode to a JSON object.
     */
    public static function parse(string $didDocument): array
    {
        try {
            $decoded = json_decode($didDocument, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new InvalidArgumentException('Invalid DID document: ' . $e->getMessage(), 0, $e);
        }

        if (!is_array($decoded)) {
            throw new InvalidArgumentException('Invalid DID document: expected JSON object, got ' . get_debug_type($decoded));
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * Extract JWKs from a DID document and parse them into Key objects.
     *
     * @param string|array<string, mixed> $didDocument The DID document as a JSON string or pre-decoded array.
     *
     * @return array<string, Key>
     *
     * @throws InvalidArgumentException When the DID document is malformed
     *                                  or contains no usable JWKs.
     */
    public static function parseToKeyArray(string|array $didDocument): array
    {
        if (is_string($didDocument)) {
            $didDocument = self::parse($didDocument);
        }

        if (!isset($didDocument['assertionMethod']) || !is_array($didDocument['assertionMethod'])) {
            throw new InvalidArgumentException('DID document has no valid assertionMethod array');
        }

        $keys = [];

        foreach ($didDocument['assertionMethod'] as $entry) {
            if (!is_array($entry)) {
                continue;
            }

            $type = $entry['type'] ?? null;
            if ($type !== 'JsonWebKey') {
                continue;
            }

            $jwk = $entry['publicKeyJwk'] ?? null;
            if (!is_array($jwk)) {
                continue;
            }

            $alg = $jwk['alg'] ?? null;
            if (!is_string($alg) || $alg === '') {
                continue;
            }

            $id = $entry['id'] ?? null;
            if (!is_string($id) || $id === '') {
                continue;
            }

            // Inject `kid` into the JWK if not already present so that
            // firebase/php-jwt can index the keyset by `kid`.
            if (!isset($jwk['kid'])) {
                $jwk['kid'] = $id;
            }

            $parsedKey = JWK::parseKey($jwk, $alg);
            if (!$parsedKey instanceof Key) {
                continue;
            }

            $keys[$id] = $parsedKey;
        }

        if ($keys === []) {
            throw new InvalidArgumentException('No valid keys found in DID document');
        }

        return $keys;
    }
}
