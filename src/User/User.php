<?php

declare(strict_types=1);

namespace Oro\Security\User;

use Assert\Assertion;
use Daikon\EventSourcing\Aggregate\AggregateRootInterface;
use Daikon\EventSourcing\Aggregate\AggregateRootTrait;
use Oro\Security\Entity\AuthToken;
use Oro\Security\Entity\VerifyToken;
use Oro\Security\User\Activate\ActivateUser;
use Oro\Security\User\Activate\UserWasActivated;
use Oro\Security\User\Login\LoginUser;
use Oro\Security\User\Login\UserWasLoggedIn;
use Oro\Security\User\Logout\LogoutUser;
use Oro\Security\User\Logout\AuthTokenWasReset;
use Oro\Security\User\Logout\UserWasLoggedOut;
use Oro\Security\User\Register\AuthTokenWasAdded;
use Oro\Security\User\Register\RegisterUser;
use Oro\Security\User\Register\UserWasRegistered;
use Oro\Security\User\Register\VerifyTokenWasAdded;
use Oro\Security\ValueObject\UserState;

final class User implements AggregateRootInterface
{
    use AggregateRootTrait;

    /** @var UserState */
    private $currentState;

    /** @var VerifyToken */
    private $verificationToken;

    /** @var AuthToken */
    private $authToken;

    public function getCurrentState(): UserState
    {
        return $this->currentState;
    }

    public static function register(RegisterUser $registerUser): self
    {
        return (new self($registerUser->getAggregateId()))
            ->reflectThat(UserWasRegistered::fromCommand($registerUser))
            ->reflectThat(AuthTokenWasAdded::fromCommand($registerUser))
            ->reflectThat(VerifyTokenWasAdded::fromCommand($registerUser));
    }

    public function activate(ActivateUser $activateUser): self
    {
        Assertion::notNull($this->verificationToken, 'User has no pending activation.');
        Assertion::true(
            !$this->currentState->isDeactivated() || !$this->currentState->isDeleted(),
            'User activation is not allowed within the current state.'
        );

        return $this->reflectThat(UserWasActivated::fromCommand($activateUser));
    }

    public function login(LoginUser $loginUser): self
    {
        Assertion::notNull($this->authToken, 'User has no authentication token.');

        return $this->reflectThat(UserWasLoggedIn::fromCommand($loginUser));
    }

    public function logout(LogoutUser $logoutUser): self
    {
        Assertion::notNull($this->authToken, 'User has no authentication token.');

        return $this->reflectThat(UserWasLoggedOut::fromCommand($logoutUser))
            ->reflectThat(AuthTokenWasReset::fromCommand($logoutUser));
    }

    protected function whenUserWasRegistered(UserWasRegistered $userRegistered): void
    {
        $this->currentState = UserState::fromNative(UserState::UNVERIFIED);
    }

    protected function whenAuthTokenWasAdded(AuthTokenWasAdded $tokenAdded): void
    {
        $this->authToken = AuthToken::fromNative([
            'id' => (string)$tokenAdded->getId(),
            'token' => (string)$tokenAdded->getToken(),
            'expiresAt' => (string)$tokenAdded->getExpiresAt()
        ]);
    }

    protected function whenVerifyTokenWasAdded(VerifyTokenWasAdded $tokenAdded): void
    {
        $this->verificationToken = VerifyToken::fromNative([
            'id' => (string)$tokenAdded->getId(),
            'token' => (string)$tokenAdded->getToken()
        ]);
    }

    protected function whenUserWasActivated(UserWasActivated $userActivated): void
    {
        $this->currentState = UserState::fromNative(UserState::ACTIVATED);
        $this->verificationToken = null;
    }

    protected function whenUserWasLoggedOut(UserWasLoggedOut $userLoggedOut): void
    {
    }

    protected function whenUserWasLoggedIn(UserWasLoggedIn $userLoggedIn): void
    {
        $this->authToken = $this->authToken->withExpiresAt($userLoggedIn->getAuthTokenExpiresAt());
    }

    protected function whenAuthTokenWasReset(AuthTokenWasReset $tokenReset): void
    {
        $this->authToken = AuthToken::fromNative([
            'id' => (string)$tokenReset->getId(),
            'token' => (string)$tokenReset->getToken(),
            'expiresAt' => (string)$tokenReset->getExpiresAt()
        ]);
    }
}
