<?php

namespace SecureCipher\Enum;

/**
 * <p>Description of CipherMethod
 * Enum obtained with a simple script:
  <pre>foreach(openssl_get_cipher_methods() as $m){
  file_put_contents("methods.txt", "case ".strtoupper(str_replace("-", "_", $m)) ."='".$m."';".PHP_EOL, FILE_APPEND);
  }</pre></p>
 * @author Stefano Perrini <perrini.stefano@gmail.com> aka La Matrigna
 * 
 */
enum CipherMethod: string {

    case AES_128_CBC = 'aes-128-cbc';
    case AES_128_CBC_CTS = 'aes-128-cbc-cts';
    case AES_128_CBC_HMAC_SHA1 = 'aes-128-cbc-hmac-sha1';
    case AES_128_CBC_HMAC_SHA256 = 'aes-128-cbc-hmac-sha256';
    case AES_128_CCM = 'aes-128-ccm';
    case AES_128_CFB = 'aes-128-cfb';
    case AES_128_CFB1 = 'aes-128-cfb1';
    case AES_128_CFB8 = 'aes-128-cfb8';
    case AES_128_CTR = 'aes-128-ctr';
    case AES_128_ECB = 'aes-128-ecb';
    case AES_128_GCM = 'aes-128-gcm';
    case AES_128_OCB = 'aes-128-ocb';
    case AES_128_OFB = 'aes-128-ofb';
    case AES_128_SIV = 'aes-128-siv';
    case AES_128_WRAP = 'aes-128-wrap';
    case AES_128_WRAP_INV = 'aes-128-wrap-inv';
    case AES_128_WRAP_PAD = 'aes-128-wrap-pad';
    case AES_128_WRAP_PAD_INV = 'aes-128-wrap-pad-inv';
    case AES_128_XTS = 'aes-128-xts';
    case AES_192_CBC = 'aes-192-cbc';
    case AES_192_CBC_CTS = 'aes-192-cbc-cts';
    case AES_192_CCM = 'aes-192-ccm';
    case AES_192_CFB = 'aes-192-cfb';
    case AES_192_CFB1 = 'aes-192-cfb1';
    case AES_192_CFB8 = 'aes-192-cfb8';
    case AES_192_CTR = 'aes-192-ctr';
    case AES_192_ECB = 'aes-192-ecb';
    case AES_192_GCM = 'aes-192-gcm';
    case AES_192_OCB = 'aes-192-ocb';
    case AES_192_OFB = 'aes-192-ofb';
    case AES_192_SIV = 'aes-192-siv';
    case AES_192_WRAP = 'aes-192-wrap';
    case AES_192_WRAP_INV = 'aes-192-wrap-inv';
    case AES_192_WRAP_PAD = 'aes-192-wrap-pad';
    case AES_192_WRAP_PAD_INV = 'aes-192-wrap-pad-inv';
    case AES_256_CBC = 'aes-256-cbc';
    case AES_256_CBC_CTS = 'aes-256-cbc-cts';
    case AES_256_CBC_HMAC_SHA1 = 'aes-256-cbc-hmac-sha1';
    case AES_256_CBC_HMAC_SHA256 = 'aes-256-cbc-hmac-sha256';
    case AES_256_CCM = 'aes-256-ccm';
    case AES_256_CFB = 'aes-256-cfb';
    case AES_256_CFB1 = 'aes-256-cfb1';
    case AES_256_CFB8 = 'aes-256-cfb8';
    case AES_256_CTR = 'aes-256-ctr';
    case AES_256_ECB = 'aes-256-ecb';
    case AES_256_GCM = 'aes-256-gcm';
    case AES_256_OCB = 'aes-256-ocb';
    case AES_256_OFB = 'aes-256-ofb';
    case AES_256_SIV = 'aes-256-siv';
    case AES_256_WRAP = 'aes-256-wrap';
    case AES_256_WRAP_INV = 'aes-256-wrap-inv';
    case AES_256_WRAP_PAD = 'aes-256-wrap-pad';
    case AES_256_WRAP_PAD_INV = 'aes-256-wrap-pad-inv';
    case AES_256_XTS = 'aes-256-xts';
    case ARIA_128_CBC = 'aria-128-cbc';
    case ARIA_128_CCM = 'aria-128-ccm';
    case ARIA_128_CFB = 'aria-128-cfb';
    case ARIA_128_CFB1 = 'aria-128-cfb1';
    case ARIA_128_CFB8 = 'aria-128-cfb8';
    case ARIA_128_CTR = 'aria-128-ctr';
    case ARIA_128_ECB = 'aria-128-ecb';
    case ARIA_128_GCM = 'aria-128-gcm';
    case ARIA_128_OFB = 'aria-128-ofb';
    case ARIA_192_CBC = 'aria-192-cbc';
    case ARIA_192_CCM = 'aria-192-ccm';
    case ARIA_192_CFB = 'aria-192-cfb';
    case ARIA_192_CFB1 = 'aria-192-cfb1';
    case ARIA_192_CFB8 = 'aria-192-cfb8';
    case ARIA_192_CTR = 'aria-192-ctr';
    case ARIA_192_ECB = 'aria-192-ecb';
    case ARIA_192_GCM = 'aria-192-gcm';
    case ARIA_192_OFB = 'aria-192-ofb';
    case ARIA_256_CBC = 'aria-256-cbc';
    case ARIA_256_CCM = 'aria-256-ccm';
    case ARIA_256_CFB = 'aria-256-cfb';
    case ARIA_256_CFB1 = 'aria-256-cfb1';
    case ARIA_256_CFB8 = 'aria-256-cfb8';
    case ARIA_256_CTR = 'aria-256-ctr';
    case ARIA_256_ECB = 'aria-256-ecb';
    case ARIA_256_GCM = 'aria-256-gcm';
    case ARIA_256_OFB = 'aria-256-ofb';
    case CAMELLIA_128_CBC = 'camellia-128-cbc';
    case CAMELLIA_128_CBC_CTS = 'camellia-128-cbc-cts';
    case CAMELLIA_128_CFB = 'camellia-128-cfb';
    case CAMELLIA_128_CFB1 = 'camellia-128-cfb1';
    case CAMELLIA_128_CFB8 = 'camellia-128-cfb8';
    case CAMELLIA_128_CTR = 'camellia-128-ctr';
    case CAMELLIA_128_ECB = 'camellia-128-ecb';
    case CAMELLIA_128_OFB = 'camellia-128-ofb';
    case CAMELLIA_192_CBC = 'camellia-192-cbc';
    case CAMELLIA_192_CBC_CTS = 'camellia-192-cbc-cts';
    case CAMELLIA_192_CFB = 'camellia-192-cfb';
    case CAMELLIA_192_CFB1 = 'camellia-192-cfb1';
    case CAMELLIA_192_CFB8 = 'camellia-192-cfb8';
    case CAMELLIA_192_CTR = 'camellia-192-ctr';
    case CAMELLIA_192_ECB = 'camellia-192-ecb';
    case CAMELLIA_192_OFB = 'camellia-192-ofb';
    case CAMELLIA_256_CBC = 'camellia-256-cbc';
    case CAMELLIA_256_CBC_CTS = 'camellia-256-cbc-cts';
    case CAMELLIA_256_CFB = 'camellia-256-cfb';
    case CAMELLIA_256_CFB1 = 'camellia-256-cfb1';
    case CAMELLIA_256_CFB8 = 'camellia-256-cfb8';
    case CAMELLIA_256_CTR = 'camellia-256-ctr';
    case CAMELLIA_256_ECB = 'camellia-256-ecb';
    case CAMELLIA_256_OFB = 'camellia-256-ofb';
    case CHACHA20 = 'chacha20';
    case CHACHA20_POLY1305 = 'chacha20-poly1305';
    case DES_EDE_CBC = 'des-ede-cbc';
    case DES_EDE_CFB = 'des-ede-cfb';
    case DES_EDE_ECB = 'des-ede-ecb';
    case DES_EDE_OFB = 'des-ede-ofb';
    case DES_EDE3_CBC = 'des-ede3-cbc';
    case DES_EDE3_CFB = 'des-ede3-cfb';
    case DES_EDE3_CFB1 = 'des-ede3-cfb1';
    case DES_EDE3_CFB8 = 'des-ede3-cfb8';
    case DES_EDE3_ECB = 'des-ede3-ecb';
    case DES_EDE3_OFB = 'des-ede3-ofb';
    case DES3_WRAP = 'des3-wrap';
    case SM4_CBC = 'sm4-cbc';
    case SM4_CFB = 'sm4-cfb';
    case SM4_CTR = 'sm4-ctr';
    case SM4_ECB = 'sm4-ecb';
    case SM4_OFB = 'sm4-ofb';
}
