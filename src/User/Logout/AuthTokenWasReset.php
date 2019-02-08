<?php

declare(strict_types=1);

namespace Oro\Security\User\Logout;

use Daikon\Entity\ValueObject\Timestamp;
use Daikon\Entity\ValueObject\Uuid;
use Daikon\EventSourcing\Aggregate\Event\DomainEvent;
use Daikon\EventSourcing\Aggregate\Event\DomainEventInterface;
use Daikon\Interop\FromToNativeTrait;
use Oro\Security\ValueObject\RandomToken;

/**
 * @map(aggregateId, Daikon\EventSourcing\Aggregate\AggregateId::fromNative)
 * @map(aggregateRevision, Daikon\EventSourcing\Aggregate\AggregateRevision::fromNative)
 * @map(id, Daikon\Entity\ValueObject\Uuid::fromNative)
 * @map(token, Oro\Security\ValueObject\RandomToken::fromNative)
 * @map(expiresAt, Daikon\Entity\ValueObject\Timestamp::fromNative)
 */
final class AuthTokenWasReset extends DomainEvent
{
    use FromToNativeTrait;

    /** @var Uuid */
    private $id;

    /** @var RandomToken */
    private $token;

    /** @var Timestamp */
    private $expiresAt;

    public static function fromCommand(LogoutUser $logoutUser): self
    {
        return self::fromNative([
            'aggregateId' => (string)$logoutUser->getAggregateId(),
            'id' => (string)Uuid::generate(),
            'token' => (string)RandomToken::generate(),
            'expiresAt' => gmdate(Timestamp::NATIVE_FORMAT, 0)
        ]);
    }

    public function conflictsWith(DomainEventInterface $otherEvent): bool
    {
        return false;
    }

    public function getId(): Uuid
    {
        return $this->id;
    }

    public function getToken(): RandomToken
    {
        return $this->token;
    }

    public function getExpiresAt(): Timestamp
    {
        return $this->expiresAt;
    }
}
