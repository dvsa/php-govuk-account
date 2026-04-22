<?php

declare(strict_types=1);

namespace Dvsa\GovUkAccount\Helper;

use InvalidArgumentException;

/**
 * Small set of strict, defence-in-depth assertions used to narrow `mixed`
 * values that originate from external inputs (configuration arrays,
 * JWT claim arrays, decoded JSON responses, etc.) into the concrete
 * scalar types the rest of the codebase relies upon.
 *
 * These helpers throw early and with a precise context-aware message
 * rather than allowing a `TypeError` (or, worse, a silent type coercion)
 * to surface deeper in the call stack.
 *
 * @internal
 */
final class Assert
{
    /**
     * @param array<array-key, mixed> $array
     */
    public static function requireString(array $array, string $context, string ...$path): string
    {
        $value = self::traverse($array, $context, array_values($path));

        if (!is_string($value)) {
            throw new InvalidArgumentException(sprintf(
                '%s: option "%s" must be a string, got %s',
                $context,
                implode('.', $path),
                get_debug_type($value),
            ));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $array
     *
     * @return array<array-key, mixed>
     */
    public static function requireArray(array $array, string $context, string ...$path): array
    {
        $value = self::traverse($array, $context, array_values($path));

        if (!is_array($value)) {
            throw new InvalidArgumentException(sprintf(
                '%s: option "%s" must be an array, got %s',
                $context,
                implode('.', $path),
                get_debug_type($value),
            ));
        }

        return $value;
    }

    /**
     * Stringifies an arbitrary value safely for inclusion in user-facing
     * error messages. Avoids leaking object internals or causing a
     * `__toString` side-effect; falls back to `get_debug_type` for
     * non-scalar values.
     */
    public static function describe(mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }
        if ($value === null || is_scalar($value)) {
            return var_export($value, true);
        }

        return get_debug_type($value);
    }

    /**
     * @param array<array-key, mixed> $array
     * @param list<string>            $path
     */
    private static function traverse(array $array, string $context, array $path): mixed
    {
        if ($path === []) {
            throw new InvalidArgumentException($context . ': empty option path supplied');
        }

        $cursor = $array;
        foreach ($path as $segment) {
            if (!is_array($cursor) || !array_key_exists($segment, $cursor)) {
                throw new InvalidArgumentException(sprintf(
                    '%s: required option "%s" is missing',
                    $context,
                    implode('.', $path),
                ));
            }
            $cursor = $cursor[$segment];
        }

        return $cursor;
    }
}
