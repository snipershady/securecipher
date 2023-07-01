# securecipher

A free and easy-to-use string encrypter and decrypter tool

## Use case

``` php

<?php

use SecureCipher\Service\SecureCipher;

        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $encryptedData = $sc->encrypt($data, $userKey);

        $retrievedData = $sc->decrypt($encryptedData, $userKey);

        // $encryptedData === $retrievedData // true
```