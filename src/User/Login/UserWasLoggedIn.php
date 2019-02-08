<?php

declare(strict_types=1);

namespace Oro\Security\User\Login;

use Daikon\Entity\ValueObject\Timestamp;
use Daikon\EventSourcing\Aggregate\Event\DomainEvent;
use Daikon\EventSourcing\Aggregate\Event\DomainEventInterface;
use Daikon\Interop\FromToNativeTrait;

/**
 * @map(aggregateId, Daikon\EventSourcing\Aggregate\AggregateId::fromNative)
 * @map(aggregateRevision, Daikon\EventSourcing\Aggregate\AggregateRevision::fromNative)
 * @map(authTokenExpiresAt, Daikon\Entity\ValueObject\Timestamp::fromNative)
 */
final class UserWasLoggedIn extends DomainEvent
{
    use FromToNativeTrait;

    /** @var Timestamp */
    private $authTokenExpiresAt;

    public static function fromCommand(LoginUser $loginUser): self
    {
        return self::fromNative($loginUser->toNative());
    }

    public function conflictsWith(DomainEventInterface $otherEvent): bool
    {
        return false;
    }

    public function getAuthTokenExpiresAt(): Timestamp
    {
        return $this->authTokenExpiresAt;
    }
}
