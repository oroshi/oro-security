<?php

declare(strict_types=1);

namespace Oro\Security\ValueObject;

use Assert\Assertion;
use Daikon\Interop\ValueObjectInterface;

final class UserRole implements ValueObjectInterface
{
    public const DEFAULT = 'user';

    private const ROLES = [
        self::DEFAULT,
        'administrator'
    ];

    private $role;

    public static function fromNative($nativeValue): ValueObjectInterface
    {
        Assertion::inArray($nativeValue, self::ROLES);
        return new self($nativeValue);
    }

    public function toNative()
    {
        return $this->role;
    }

    public function equals(ValueObjectInterface $otherValue): bool
    {
        Assertion::isInstanceOf($otherValue, self::class);
        return $this->toNative() === $otherValue->toNative();
    }

    public function __toString(): string
    {
        return $this->toNative();
    }

    private function __construct(string $role)
    {
        $this->role = $role;
    }
}
