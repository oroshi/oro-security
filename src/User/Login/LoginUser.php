<?php

declare(strict_types=1);

namespace Oro\Security\User\Login;

use Daikon\Entity\ValueObject\Timestamp;
use Daikon\EventSourcing\Aggregate\Command\Command;
use Daikon\Interop\FromToNativeTrait;

/**
 * @map(aggregateId, Daikon\EventSourcing\Aggregate\AggregateId::fromNative)
 * @map(knownAggregateRevision, Daikon\EventSourcing\Aggregate\AggregateRevision::fromNative)
 * @map(authTokenExpiresAt, Daikon\Entity\ValueObject\Timestamp::fromNative)
 */
final class LoginUser extends Command
{
    /** @var Timestamp */
    private $authTokenExpiresAt;

    use FromToNativeTrait;

    public function getAuthTokenExpiresAt(): Timestamp
    {
        return $this->authTokenExpiresAt;
    }
}
