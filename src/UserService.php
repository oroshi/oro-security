<?php

declare(strict_types=1);

namespace Oro\Security;

use Assert\Assertion;
use Daikon\Config\ConfigProviderInterface;
use Daikon\Entity\ValueObject\Timestamp;
use Daikon\Entity\ValueObject\Uuid;
use Daikon\EventSourcing\Aggregate\Command\CommandInterface;
use Daikon\MessageBus\MessageBusInterface;
use Firebase\JWT\JWT;
use Oro\Security\ReadModel\Standard\User;
use Oro\Security\ReadModel\Standard\Users;
use Oro\Security\User\Activate\ActivateUser;
use Oro\Security\User\Login\LoginUser;
use Oro\Security\User\Logout\LogoutUser;
use Oro\Security\User\Register\RegisterUser;
use Oro\Security\ValueObject\PasswordHash;
use Oro\Security\ValueObject\RandomToken;
use Oro\Security\ValueObject\UserRole;

final class UserService
{
    const CHAN_COMMANDS = 'commands';

    const DEFAULT_TOKEN_EXPIRY = '+1 month';

    /** @var ConfigProviderInterface */
    private $config;

     /** @var MessageBusInterface */
    private $messageBus;

    /** @var Users */
    private $users;

    public function __construct(ConfigProviderInterface $config, MessageBusInterface $messageBus, Users $users)
    {
        $this->config = $config;
        $this->messageBus = $messageBus;
        $this->users = $users;
    }

    public function register(array $userInfos, UserRole $role = null): RegisterUser
    {
        Assertion::keyIsset($userInfos, 'password');
        $userInfos = array_merge($userInfos, [
            'role' => (string)($role ?? 'user'),
            'aggregateId' => 'oro.security.user-'.Uuid::generate(),
            'passwordHash' => (string)PasswordHash::gen($userInfos['password']),
            'authTokenExpiresAt' => gmdate(Timestamp::NATIVE_FORMAT, $this->getTokenExpiryTime())
        ]);
        $userRegistration = RegisterUser::fromNative($userInfos);
        $this->dispatch($userRegistration);
        return $userRegistration;
    }

    public function activate(User $user): void
    {
        $activateUser = ActivateUser::fromNative([
            'aggregateId' => (string)$user->getAggregateId()
        ]);
        $this->dispatch($activateUser);
    }

    public function authenticate(string $username, string $password): ?User
    {
        if (!$user = $this->users->byUsername($username)) {
            return null;
        }
        if (!$hash = $user->getPasswordHash()) {
            return null;
        }
        return $hash->verify($password) ? $user : null;
    }

    public function login(User $user): void
    {
        $loginUser = LoginUser::fromNative([
            'aggregateId' => (string)$user->getAggregateId(),
            'authTokenExpiresAt' => gmdate(Timestamp::NATIVE_FORMAT, $this->getTokenExpiryTime())
        ]);
        $this->dispatch($loginUser);
    }

    public function logout(string $userId): void
    {
        $logoutUser = LogoutUser::fromNative([
            'aggregateId' => $userId
        ]);
        $this->dispatch($logoutUser);
    }

    public function generateJWT(User $user): string
    {
        $authToken = $user->getAuthToken();
        $secretKey = $this->config->get('crates.oro.security.jwt.secret', 'oroshi');

        return JWT::encode([
            'iss' => $this->config->get('crates.oro.security.jwt.issuer', 'oroshi'),
            'aud' => $this->config->get('crates.oro.security.jwt.audience', 'oroshi'),
            'exp' => $this->getTokenExpiryTime(),
            'nbf' => time(),
            'iat' => time(),
            'jti' => (string)$authToken->getId(),
            'xsrf' => (string)$authToken->getToken(),
            'uid' => (string)$user->getAggregateId()
        ], $secretKey);
    }

    private function dispatch(CommandInterface $command): void
    {
        $this->messageBus->publish($command, self::CHAN_COMMANDS);
    }

    private function getTokenExpiryTime()
    {
        return strtotime(
            $this->config->get('crates.oro.security.login.token_expiry', self::DEFAULT_TOKEN_EXPIRY)
        );
    }
}
