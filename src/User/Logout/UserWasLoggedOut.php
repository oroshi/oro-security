<?php

declare(strict_types=1);

namespace Oro\Security\User\Logout;

use Daikon\EventSourcing\Aggregate\Event\DomainEvent;
use Daikon\EventSourcing\Aggregate\Event\DomainEventInterface;
use Daikon\Interop\FromToNativeTrait;

/**
 * @map(aggregateId, Daikon\EventSourcing\Aggregate\AggregateId::fromNative)
 * @map(aggregateRevision, Daikon\EventSourcing\Aggregate\AggregateRevision::fromNative)
 */
final class UserWasLoggedOut extends DomainEvent
{
    use FromToNativeTrait;

    public static function fromCommand(LogoutUser $logoutUser): self
    {
        return self::fromNative($logoutUser->toNative());
    }

    public function conflictsWith(DomainEventInterface $otherEvent): bool
    {
        return false;
    }
}
