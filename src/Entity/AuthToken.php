<?php

declare(strict_types=1);

namespace Oro\Security\Entity;

use Daikon\Entity\Entity\Attribute;
use Daikon\Entity\Entity\AttributeMap;
use Daikon\Entity\Entity\Entity;
use Daikon\Entity\ValueObject\Timestamp;
use Daikon\Entity\ValueObject\Uuid;
use Daikon\Interop\ValueObjectInterface;
use Oro\Security\ValueObject\RandomToken;

final class AuthToken extends Entity
{
    public static function getAttributeMap(): AttributeMap
    {
        return new AttributeMap([
            Attribute::define('id', Uuid::class),
            Attribute::define('token', RandomToken::class),
            Attribute::define('expiresAt', Timestamp::class)
        ]);
    }

    public function getIdentity(): ValueObjectInterface
    {
        return $this->getId();
    }

    public function getId(): Uuid
    {
        return $this->get('id');
    }

    public function getToken(): RandomToken
    {
        return $this->get('token');
    }

    public function getExpiresAt(): Timestamp
    {
        return $this->get('expiresAt');
    }

    public function withToken(RandomToken $token): self
    {
        return $this->withValue('token', $token);
    }

    public function withExpiresAt(Timestamp $expiresAt): self
    {
        return $this->withValue('expiresAt', $expiresAt);
    }
}
