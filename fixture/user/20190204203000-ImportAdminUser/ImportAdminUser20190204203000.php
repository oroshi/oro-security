<?php

namespace Oro\Security\Fixture;

use Daikon\MessageBus\MessageBusInterface;
use Oroshi\Core\Fixture\FixtureInterface;
use Oroshi\Core\Fixture\FixtureTrait;

final class ImportAdminUser20190204203000 implements FixtureInterface
{
    use FixtureTrait;

    public function import(MessageBusInterface $messageBus): void
    {
        foreach ($this->loadFile('admin-user-data.json') as $fixture) {
            $command = $fixture['@type']::fromNative($fixture['values']);
            $messageBus->publish($command, self::CHAN_COMMANDS);
        }
    }

    private function loadFile(string $filename): array
    {
        return json_decode(file_get_contents(__DIR__."/$filename"), true);
    }
}
