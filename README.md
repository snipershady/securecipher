# securecipher

A free, reliable and easy-to-use cipher to encrypt and decrypt strings

## Context
You need to encrypt some data to increase your cybersecurity level

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

``` php

## Cipher Method enumeration.
The default value is AES_256_CBC, but you can select another one with CipherMethod enumeration instances

<?php

use SecureCipher\Service\SecureCipher;
use SecureCipher\Enum\CipherMethod;
...
...
$encryptedData = $sc->encrypt($data, $userKey, CipherMethod::AES_128_CBC);             // You can select another cipher method from Enum\CipherMethod
$retrievedData = $sc->decrypt($encryptedData, $userKey, CipherMethod::AES_128_CBC);    // Cipher method must be the same for encryption and decryption 
```