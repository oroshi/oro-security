<?php

declare(strict_types=1);

namespace Oro\Security\Entity;

use Daikon\Entity\Entity\Attribute;
use Daikon\Entity\Entity\AttributeMap;
use Daikon\Entity\Entity\Entity;
use Daikon\Entity\ValueObject\Email;
use Daikon\Entity\ValueObject\Text;
use Daikon\EventSourcing\Aggregate\AggregateId;
use Daikon\EventSourcing\Aggregate\AggregateRevision;
use Daikon\EventSourcing\Aggregate\Event\DomainEventInterface;
use Daikon\Interop\ValueObjectInterface;
use Oro\Security\ValueObject\PasswordHash;
use Oro\Security\ValueObject\UserRole;
use Oro\Security\ValueObject\UserState;
use Oro\Security\ValueObject\UserTokenList;

final class UserProperties extends Entity
{
    public static function getAttributeMap(): AttributeMap
    {
        return new AttributeMap([
            Attribute::define('aggregateId', AggregateId::class),
            Attribute::define('aggregateRevision', AggregateRevision::class),
            Attribute::define('username', Text::class),
            Attribute::define('email', Email::class),
            Attribute::define('role', UserRole::class),
            Attribute::define('locale', Text::class),
            Attribute::define('passwordHash', PasswordHash::class),
            Attribute::define('state', UserState::class),
            Attribute::define('tokens', UserTokenList::class)
        ]);
    }

    public function getIdentity(): ValueObjectInterface
    {
        return $this->getAggregateId();
    }

    public function getAggregateId(): AggregateId
    {
        return $this->get('aggregateId');
    }

    public function getAggregateRevision(): AggregateRevision
    {
        return $this->get('aggregateRevision');
    }

    public function adaptRevision(DomainEventInterface $event): self
    {
        return $this->withValue('aggregateRevision', $event->getAggregateRevision()->toNative());
    }

    public function getUsername(): Text
    {
        return $this->get('username');
    }

    public function getEmail(): Email
    {
        return $this->get('email');
    }

    public function getRole(): UserRole
    {
        return $this->get('role');
    }

    public function getLocale(): Text
    {
        return $this->get('locale');
    }

    public function getPasswordHash(): PasswordHash
    {
        return $this->get('passwordHash');
    }

    public function getState(): UserState
    {
        return $this->get('state');
    }

    public function withState(UserState $state): self
    {
        return $this->withValue('state', $state);
    }

    public function getTokens(): UserTokenList
    {
        return $this->get('tokens') ?? UserTokenList::makeEmpty();
    }

    public function getAuthToken(): ?AuthToken
    {
        return $this->getTokens()->byType(AuthToken::class);
    }

    public function getVerifyToken(): ?VerifyToken
    {
        return $this->getTokens()->byType(VerifyToken::class);
    }

    public function withAuthTokenAdded(AuthToken $authToken): self
    {
        return $this->withValue('tokens', $this->getTokens()->push($authToken));
    }

    public function withAuthTokenReplaced(AuthToken $authToken)
    {
        $tokens = $this->getTokens()->remove($this->getAuthToken());
        return $this->withValue('tokens', $tokens->push($authToken));
    }

    public function withVerifyTokenAdded(VerifyToken $verifyToken): self
    {
        return $this->withValue('tokens', $this->getTokens()->push($verifyToken));
    }

    public function withVerifyTokenRemoved(): self
    {
        if ($verifyToken = $this->getVerifyToken()) {
            return $this->withValue('tokens', $this->getTokens()->remove($verifyToken));
        }
        return $this;
    }
}
