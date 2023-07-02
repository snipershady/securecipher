<?php

namespace SecureCipher\Service;

use InvalidArgumentException;
use SecureCipher\Enum\CipherMethod;
use const OPENSSL_RAW_DATA;
use function base64_decode;
use function base64_encode;
use function hash;
use function hash_equals;
use function hash_hmac;
use function openssl_cipher_iv_length;
use function openssl_decrypt;
use function openssl_encrypt;
use function openssl_random_pseudo_bytes;
use function substr;

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
 * Description of SecureCipher
 *
 * @author Stefano Perrini <perrini.stefano@gmail.com> aka La Matrigna
 */
class SecureCipher {

    private string $baseKey;

    /**
     * 
     * @param string $baseKey
     */
    public function __construct(string $baseKey) {
        $this->baseKey = $baseKey;
    }

    /**
     * 
     * @param string $data
     * @param string $userKey
     * @param CipherMethod $method <p>Default value AES_256_CBC Enumeration case from SecureCipher\Enum\CipherMethod</p>
     * @return string
     * @throws InvalidArgumentException
     */
    public function encrypt(string $data, string $userKey, CipherMethod $method = CipherMethod::AES_256_CBC): string {
        $this->checkEmptyKey($userKey);
        $this->checkEmptyKey($this->baseKey);
        $firstKey = hash("sha3-512", base64_encode($userKey));
        $secondKey = hash("sha3-512", base64_encode($this->baseKey));
        $ivLength = (int) openssl_cipher_iv_length($method->value);
        $iv = openssl_random_pseudo_bytes($ivLength);
        $firstEncrypted = (string) openssl_encrypt($data, $method->value, $firstKey, OPENSSL_RAW_DATA, $iv);
        $secondEncrypted = hash_hmac('sha3-512', $firstEncrypted, $secondKey, true);
        $output = base64_encode($iv . $secondEncrypted . $firstEncrypted);
        return $output;
    }

    /**
     * 
     * @param string $input
     * @param string $userKey
     * @param CipherMethod $method <p>Default value AES_256_CBC Enumeration case from SecureCipher\Enum\CipherMethod</p>
     * @return string
     * @throws InvalidArgumentException
     */
    public function decrypt(string $input, string $userKey, CipherMethod $method = CipherMethod::AES_256_CBC): string {
        $this->checkEmptyKey($userKey);
        $this->checkEmptyKey($this->baseKey);
        $firstKey = hash("sha3-512", base64_encode($userKey));
        $secondKey = hash("sha3-512", base64_encode($this->baseKey));
        $mix = base64_decode($input);
        $ivLength = (int) openssl_cipher_iv_length($method->value);
        $iv = substr($mix, 0, $ivLength);
        $secondEncrypted = substr($mix, $ivLength, 64);
        $firstEncrypted = substr($mix, $ivLength + 64);
        $data = (string) openssl_decrypt($firstEncrypted, $method->value, $firstKey, OPENSSL_RAW_DATA, $iv);
        $secondEncryptedHm = hash_hmac('sha3-512', $firstEncrypted, $secondKey, true);

        if (hash_equals($secondEncrypted, $secondEncryptedHm)) {
            return $data;
        } else {
            return "";
        }
    }

    /**
     * 
     * @param string $key
     * @return void
     * @throws InvalidArgumentException
     */
    private function checkEmptyKey(string $key): void {
        if ($key === "") {
            throw new InvalidArgumentException("You cannot use an empty key");
        }
    }
}
