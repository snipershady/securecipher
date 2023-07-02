<?php

namespace SecureCipher\Tests;

use InvalidArgumentException;
use SecureCipher\Service\SecureCipher;
use SecureCipher\Enum\CipherMethod;

/*
 * Copyright (C) 2022 Stefano Perrini <perrini.stefano@gmail.com> aka La Matrigna
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Description of ChiperTest
 *
 * @author Stefano Perrini <perrini.stefano@gmail.com> aka La Matrigna
 * @example ./vendor/phpunit/phpunit/phpunit -vvv tests/ChiperTest.php 
 */
class ChiperTest extends AbstractTestCase {

    public function testBaseString(): void {

        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $encryptedData = $sc->encrypt($data, $userKey);
        $retrievedData = $sc->decrypt($encryptedData, $userKey);

        self::assertEquals($retrievedData, $data);
        self::assertTrue(hash_equals($retrievedData, $data));
    }

    public function testBaseStringVeryLongData(): void {

        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $encryptedData = $sc->encrypt($data, $userKey);
        $retrievedData = $sc->decrypt($encryptedData, $userKey);

        self::assertEquals($retrievedData, $data);
        self::assertTrue(hash_equals($retrievedData, $data));
    }

    public function testBaseLongString(): void {
        $baseKey = base64_encode(hash("sha3-512", "baseKeyTest") . hash("sha3-512", "baseKeyTestTwo") . hash("sha3-512", "baseKeyTestThree"));
        $userKey = base64_encode(hash("sha3-512", "UserKeyTest") . hash("sha3-512", "baseKeyTestTwo") . hash("sha3-512", "baseKeyTestThree"));
        $sc = new SecureCipher($baseKey);
        $data = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
        $longData = hash("sha3-512", base64_encode($data));
        $encryptedData = $sc->encrypt($data, $userKey);
        $retrievedData = $sc->decrypt($encryptedData, $userKey);

        self::assertEquals($retrievedData, $data);
        self::assertTrue(hash_equals($retrievedData, $data));
    }

    public function testEmptyString(): void {
        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "";
        $encryptedData = $sc->encrypt($data, $userKey);
        $retrievedData = $sc->decrypt($encryptedData, $userKey);

        self::assertEquals($retrievedData, $data);
        self::assertTrue(hash_equals($retrievedData, $data));
    }

    public function testNumericString(): void {
        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "123456789";
        $encryptedData = $sc->encrypt($data, $userKey);
        $retrievedData = $sc->decrypt($encryptedData, $userKey);

        self::assertEquals($retrievedData, $data);
        self::assertTrue(hash_equals($retrievedData, $data));
    }

    public function testAlphaNumericString(): void {
        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "Forza Napoli 1926";
        $encryptedData = $sc->encrypt($data, $userKey);
        $retrievedData = $sc->decrypt($encryptedData, $userKey);

        self::assertEquals($retrievedData, $data);
        self::assertTrue(hash_equals($retrievedData, $data));
    }

    public function testSpecialCharString(): void {
        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "Forza Napoli 1926 #@!^°§";
        $encryptedData = $sc->encrypt($data, $userKey);
        $retrievedData = $sc->decrypt($encryptedData, $userKey);

        self::assertEquals($retrievedData, $data);
        self::assertTrue(hash_equals($retrievedData, $data));
    }

    public function testBaseStringLongKeys(): void {
        $baseKey = hash("sha3-512", base64_encode("test1"));
        $userKey = hash("sha3-512", base64_encode("test1uk"));
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $longData = hash("sha3-512", base64_encode($data));
        $encryptedData = $sc->encrypt($data, $userKey);
        $retrievedData = $sc->decrypt($encryptedData, $userKey);

        self::assertEquals($retrievedData, $data);
        self::assertTrue(hash_equals($retrievedData, $data));
    }

    public function testBaseStringVeryLongKeysAndData(): void {
        $baseKey = hash("sha3-512", base64_encode("test1")) . hash("sha3-512", base64_encode("test1")) . hash("sha3-512", base64_encode("test1"));
        $userKey = hash("sha3-512", base64_encode("test1uk")) . hash("sha3-512", base64_encode("test1")) . hash("sha3-512", base64_encode("test1"));
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $longData = hash("sha3-512", base64_encode($data)) . hash("sha3-512", base64_encode($data)) . hash("sha3-512", base64_encode($data)) . hash("sha3-512", base64_encode($data));
        $encryptedData = $sc->encrypt($data, $userKey);
        $retrievedData = $sc->decrypt($encryptedData, $userKey);

        self::assertEquals($retrievedData, $data);
        self::assertTrue(hash_equals($retrievedData, $data));
    }

    public function testBaseStringWithWrongUserKeyDecrypt(): void {
        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $encryptedData = $sc->encrypt($data, $userKey);

        $wrongUserKey = "test1uk_";
        $retrievedData = $sc->decrypt($encryptedData, $wrongUserKey);

        self::assertNotEquals($retrievedData, $data);
        self::assertFalse(hash_equals($retrievedData, $data));
    }

    public function testBaseStringWithWrongUserKeyDecryptAnotherChar(): void {
        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $encryptedData = $sc->encrypt($data, $userKey);

        $wrongUserKey = "test1uk ";
        $retrievedData = $sc->decrypt($encryptedData, $wrongUserKey);

        self::assertNotEquals($retrievedData, $data);
        self::assertFalse(hash_equals($retrievedData, $data));
    }

    public function testBaseStringWithWrongBaseKeyDecrypt(): void {
        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $encryptedData = $sc->encrypt($data, $userKey);

        $scTest = new SecureCipher($baseKey . "_");
        $wrongUserKey = "test1uk";
        $retrievedData = $scTest->decrypt($encryptedData, $wrongUserKey);

        self::assertNotEquals($retrievedData, $data);
        self::assertFalse(hash_equals($retrievedData, $data));
    }

    public function testBaseStringWithWrongBaseKeyDecryptAnotherEmptyChar(): void {
        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $encryptedData = $sc->encrypt($data, $userKey);

        $scTest = new SecureCipher($baseKey . " ");
        $wrongUserKey = "test1uk";
        $retrievedData = $scTest->decrypt($encryptedData, $wrongUserKey);

        self::assertNotEquals($retrievedData, $data);
        self::assertFalse(hash_equals($retrievedData, $data));
    }

    public function testBaseStringWithEmptyKeys(): void {
        $baseKey = "";
        $userKey = "";
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $this->expectException(InvalidArgumentException::class);
        $encryptedData = $sc->encrypt($data, $userKey);
        $retrievedData = $sc->decrypt($encryptedData, $userKey);
    }

    public function testBaseStringCustomChiperMethod(): void {
        $baseKey = "test1";
        $userKey = "test1uk";
        $sc = new SecureCipher($baseKey);
        $data = "ForzaNapoli";
        $method = CipherMethod::AES_128_CBC; // "aes-128-cbc";
        $encryptedData = $sc->encrypt($data, $userKey, $method);
        $retrievedData = $sc->decrypt($encryptedData, $userKey, $method);

        self::assertEquals($retrievedData, $data);
        self::assertTrue(hash_equals($retrievedData, $data));
    }
}
