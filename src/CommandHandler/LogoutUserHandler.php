<?php

declare(strict_types=1);

namespace Oro\Security\CommandHandler;

use Daikon\EventSourcing\Aggregate\Command\CommandHandler;
use Daikon\MessageBus\Metadata\Metadata;
use Oro\Security\User\Logout\LogoutUser;

final class LogoutUserHandler extends CommandHandler
{
    protected function handleLogoutUser(LogoutUser $logoutUser, Metadata $metadata): array
    {
        $user = $this->checkout(
            $logoutUser->getAggregateId(),
            $logoutUser->getKnownAggregateRevision()
        );

        return [$user->logout($logoutUser), $metadata];
    }
}
