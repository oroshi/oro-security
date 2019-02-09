<?php

use Oro\Security\Api\Activate\ActivateAction;
use Oro\Security\Api\Login\LoginAction;
use Oro\Security\Api\Logout\LogoutAction;
use Oro\Security\Api\Register\RegisterAction;
use Oro\Security\Api\User\ResourceAction;

$cratePrefix = 'oro.security';
$mount = $configProvider->get("crates.$cratePrefix.mount", '/oro/security');
$map->attach("$cratePrefix.", $mount, function ($map) {
    $map->post('user.login', '/login', LoginAction::class);
    $map->post('user.logout', '/logout', LogoutAction::class);
    $map->post('user.register', '/register', RegisterAction::class);
    $map->get('user.activate', '/activate', ActivateAction::class)->allows(['POST']);
    $map->get('user.resource', '/users/{userId}', ResourceAction::class);
});
