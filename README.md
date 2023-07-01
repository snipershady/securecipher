# securecipher

A free and easy-to-use string encrypter and decrypter tool

## Use case

``` php

<?php

use SecureCipher\Service\SecureCipher;

$baseKey = "test1";   // You can set a system base key to encrypt all data
$userKey = "test1uk"; // You can customize encryption by user with a personal userkey

$sc = new SecureCipher($baseKey);
$data = "ForzaNapoli";  // This is the original string you want to encrypt
$encryptedData = $sc->encrypt($data, $userKey);     // This is the string you will save on persistence

$retrievedData = $sc->decrypt($encryptedData, $userKey);  // To decrypt a string you need to provide user personal key

// $encryptedData === $retrievedData // true
```