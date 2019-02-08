<?php

declare(strict_types=1);

namespace Oro\Security\User\Logout;

use Daikon\Entity\ValueObject\Timestamp;
use Daikon\EventSourcing\Aggregate\Event\DomainEvent;
use Daikon\EventSourcing\Aggregate\Event\DomainEventInterface;
use Daikon\Interop\FromToNativeTrait;

/**
 * @map(aggregateId, Daikon\EventSourcing\Aggregate\AggregateId::fromNative)
 * @map(aggregateRevision, Daikon\EventSourcing\Aggregate\AggregateRevision::fromNative)
 * @map(expiresAt, Daikon\Entity\ValueObject\Timestamp::fromNative)
 */
final class AuthTokenWasRefreshed extends DomainEvent
{
    use FromToNativeTrait;

    /** @var Timestamp */
    private $expiresAt;

    public static function fromCommand(LoginUser $loginUser): self
    {
        return self::fromNative([
            'aggregateId' => (string)$loginUser->getAggregateId(),
            'expiresAt' => (string)$loginUser->getAuthTokenExpiresAt()
        ]);
    }

    public function conflictsWith(DomainEventInterface $otherEvent): bool
    {
        return false;
    }

    public function getExpiresAt(): Timestamp
    {
        return $this->expiresAt;
    }
}
