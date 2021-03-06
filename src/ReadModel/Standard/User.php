<?php

declare(strict_types=1);

namespace Oro\Security\ReadModel\Standard;

use Assert\Assertion;
use Daikon\Entity\ValueObject\Email;
use Daikon\Entity\ValueObject\Text;
use Daikon\EventSourcing\Aggregate\AggregateIdInterface;
use Daikon\EventSourcing\Aggregate\AggregateRevision;
use Daikon\ReadModel\Projection\EventHandlerTrait;
use Daikon\ReadModel\Projection\ProjectionInterface;
use Oro\Security\Entity\AuthToken;
use Oro\Security\Entity\UserProperties;
use Oro\Security\Entity\VerifyToken;
use Oro\Security\User\Activate\UserWasActivated;
use Oro\Security\User\Register\AuthTokenWasAdded;
use Oro\Security\User\Login\UserWasLoggedIn;
use Oro\Security\User\Logout\AuthTokenWasReset;
use Oro\Security\User\Logout\UserWasLoggedOut;
use Oro\Security\User\Register\UserWasRegistered;
use Oro\Security\User\Register\VerifyTokenWasAdded;
use Oro\Security\ValueObject\PasswordHash;
use Oro\Security\ValueObject\UserRole;
use Oro\Security\ValueObject\UserState;
use Oro\Security\ValueObject\UserTokenList;

final class User implements ProjectionInterface
{
    use EventHandlerTrait;

    /** @var UserProperties */
    private $userProps;

    public static function fromNative($state): self
    {
        return new self(UserProperties::fromNative($state));
    }

    public function __construct(UserProperties $userProps)
    {
        $this->userProps = $userProps;
    }

    public function getAggregateId(): AggregateIdInterface
    {
        return $this->userProps->getAggregateId();
    }

    public function getAggregateRevision(): AggregateRevision
    {
        return $this->userProps->getAggregateRevision();
    }

    public function getUsername(): Text
    {
        return $this->userProps->getUsername();
    }

    public function getEmail(): Email
    {
        return $this->userProps->getEmail();
    }

    public function getLocale(): Text
    {
        return $this->userProps->getLocale();
    }

    public function getRole(): UserRole
    {
        return $this->userProps->getRole();
    }

    public function getState(): UserState
    {
        return $this->userProps->getState();
    }

    public function getPasswordHash(): PasswordHash
    {
        return $this->userProps->getPasswordHash();
    }

    public function getTokens(): UserTokenList
    {
        return $this->userProps->getTokens();
    }

    public function getAuthToken(): AuthToken
    {
        return $this->getTokens()->byType(AuthToken::class);
    }

    public function toNative(): array
    {
        $data = $this->userProps ? $this->userProps->toNative() : [];
        $data['@type'] = self::class;
        return $data;
    }

    private function whenUserWasRegistered(UserWasRegistered $userRegistered): void
    {
        $this->userProps = UserProperties::fromNative($userRegistered->toNative())
            ->withState(UserState::fromNative(UserState::UNVERIFIED));
    }

    private function whenAuthTokenWasAdded(AuthTokenWasAdded $tokenAdded): void
    {
        $this->userProps = $this->userProps
            ->adaptRevision($tokenAdded)
            ->withAuthTokenAdded(
                AuthToken::fromNative([
                    'id' => $tokenAdded->getId(),
                    'token' => $tokenAdded->getToken(),
                    'expiresAt' => $tokenAdded->getExpiresAt()
                ])
            );
    }

    private function whenVerifyTokenWasAdded(VerifyTokenWasAdded $tokenAdded): void
    {
        $this->userProps = $this->userProps
            ->adaptRevision($tokenAdded)
            ->withVerifyTokenAdded(
                VerifyToken::fromNative([
                    'id' => $tokenAdded->getId(),
                    'token' => $tokenAdded->getToken()
                ])
            );
    }

    private function whenUserWasActivated(UserWasActivated $userActivated): void
    {
        $this->userProps = $this->userProps
            ->adaptRevision($userActivated)
            ->withState(UserState::fromNative(UserState::ACTIVATED))
            ->withVerifyTokenRemoved();
    }

    private function whenUserWasLoggedIn(UserWasLoggedIn $userLoggedIn): void
    {
        $refreshedToken = $this->getAuthToken()->withExpiresAt($userLoggedIn->getAuthTokenExpiresAt());
        $this->userProps = $this->userProps
            ->adaptRevision($userLoggedIn)
            ->withAuthTokenReplaced($refreshedToken);
    }

    private function whenUserWasLoggedOut(UserWasLoggedOut $userLoggedOut): void
    {
        $this->userProps = $this->userProps->adaptRevision($userLoggedOut);
    }

    private function whenAuthTokenWasReset(AuthTokenWasReset $tokenReset): void
    {
        $this->userProps = $this->userProps
            ->adaptRevision($tokenReset)
            ->withAuthTokenReplaced(
                AuthToken::fromNative([
                    'id' => $tokenReset->getId(),
                    'token' => $tokenReset->getToken(),
                    'expiresAt' => $tokenReset->getExpiresAt()
                ])
            );
    }
}
