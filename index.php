<?php

require "./vendor/autoload.php";

use abdelrhman\jwtpkg\jwt;

$payload = [

    'user_id' => 1,
    'role' => 'admin',
    'exp' => 1593828222
];


$secret = "7c32d31dbdd39f2111da0b1dea59e94f3ed715fd8cdf0ca3ecf354ca1a2e3e30";



$jwt = new jwt();

echo "\n".$jwt->setHeader()
    ->setPayload($payload)
    ->setSecrect($secret)
    ->generateToken()
    ->getToken() . "\n";

$jwt->printTokenComponenets();