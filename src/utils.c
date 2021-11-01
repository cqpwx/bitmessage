#include "utils.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "log.h"

/*
 * Description:
 *   Generate ECDH key
 * Input:
 *   curve:curve id
 *   x:public key x
 *   y:public key y
 *   privateKey:Generated private key
 *   privateKeyLength:Generate private key length
 *
 * Output:
 *   result:result buffer to write
 */
void generateECDHKey(unsigned short curve,
                     void* x, void* y,
                     void* privateKey, unsigned int privateKeyLength,
                     void* result);

/*
 * Description:
 *   Generate own key
 * Input:
 *   curve:curve id
 * Output:
 *   privateKey:Private key buffer
 *   publicKeyX:Public key X buffer
 *   publicKeyY:Public key Y buffer
 */
void generateKey(unsigned short curve,
                 void* privateKey, unsigned int* privateKeyLength,
                 void* publicKeyX, unsigned int* publicKeyXLength,
                 void* publicKeyY, unsigned int* publicKeyYLength);

int bmUtilsCalculateHash(void* data, unsigned int length, void* result) {
    EVP_MD_CTX* evp_ctx;
    unsigned int resultLength = 0;

    //Parameters check
    if (data == NULL || result == NULL) {
        bmLog(__FUNCTION__, "Invalid parameter!");
        return 0;
    }
    //Calculate sha512 hash
    evp_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(evp_ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(evp_ctx, data, length);
    EVP_DigestFinal_ex(evp_ctx, result, &resultLength);
    EVP_MD_CTX_free(evp_ctx);
    evp_ctx = NULL;

    return resultLength;
}

int bmUtilsCalculateDoubleHash(void* data, unsigned int length, void* result) {
    EVP_MD_CTX* evp_ctx;
    unsigned char tempBuffer[512] = { 0 };
    unsigned int tempLength;
    unsigned int resultLength;

    //Parameters check
    if (data == NULL || result == NULL) {
        bmLog(__FUNCTION__, "Invalid parameter!");
        return 0;
    }
    //First round
    tempLength = bmUtilsCalculateHash(data, length, tempBuffer);
    //Second round
    resultLength = bmUtilsCalculateHash(tempBuffer, tempLength, result);

    return resultLength;
}

int bmUtilsCalculateRipeHash(void* data, unsigned int length, void* result) {
    EVP_MD_CTX* evp_ctx;
    unsigned int resultLength = 0;

    //Parameters check
    if (data == NULL || result == NULL) {
        bmLog(__FUNCTION__, "Invalid parameter!");
        return 0;
    }
    //Calculate ripe160md hash
    evp_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(evp_ctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(evp_ctx, data, length);
    EVP_DigestFinal_ex(evp_ctx, result, &resultLength);
    EVP_MD_CTX_free(evp_ctx);
    evp_ctx = NULL;

    return resultLength;
}

int bmUtilsPointMulti(unsigned char* secret, unsigned char* result) {
    EC_KEY* k;
    BIGNUM* privkey;
    const EC_GROUP* group;
    EC_POINT* pubkey;
    int len;
    unsigned char* pubkeyBuffer;

    if (secret == NULL || result == NULL) {
        bmLog(__FUNCTION__, "Invalid parameter!");
    }

    k = EC_KEY_new_by_curve_name(714);
    privkey = BN_bin2bn(secret, 32, NULL);
    group = EC_KEY_get0_group(k);
    pubkey = EC_POINT_new(group);

    EC_POINT_mul(group, pubkey, privkey, NULL, NULL, NULL);
    EC_KEY_set_private_key(k, privkey);
    EC_KEY_set_public_key(k, pubkey);
    if (EC_KEY_check_key(k) == 0) {
        bmLog(__FUNCTION__, "Check key failed");
        return 0;
    }

    len = i2o_ECPublicKey(k, NULL);
    pubkeyBuffer = result;
    i2o_ECPublicKey(k, &pubkeyBuffer);

    EC_POINT_free(pubkey);
    BN_free(privkey);
    EC_KEY_free(k);

    return len;
}

int bmUtilsSigning(void* buffer, unsigned int bufferLength,
                   void* privateSignKey, unsigned int privateSignKeyLength,
                   void* result) {
    unsigned char publicSignKey[512] = { 0 };
    unsigned int publicSignKeyLength = 0;
    unsigned char publicSignKeyX[0x20] = { 0 };
    unsigned char publicSignKeyY[0x20] = { 0 };
    unsigned short curve;
    BIGNUM* privateKey;
    BIGNUM* publicKeyX;
    BIGNUM* publicKeyY;
    EC_KEY* key;
    const EC_GROUP* group;
    EC_POINT* publicKey;
    EVP_MD_CTX* ctx;
    unsigned char digest[512] = {0};
    unsigned int digestLength;
    unsigned int resultLength;

    //Parameter check
    if (buffer == NULL || privateSignKey == NULL || result == NULL) {
        bmLog(__FUNCTION__, "Invalid parameters!");
        return 0;
    }

    //Create keys
    //Calculate public key
    publicSignKeyLength = bmUtilsPointMulti(privateSignKey, publicSignKey);
    //Public key X
    memcpy(publicSignKeyX, publicSignKey + 1, 0x20);
    //Public key Y
    memcpy(publicSignKeyY, publicSignKey + publicSignKeyLength - 0x20, 0x20);
    //curve
    curve = 0x02ca;
    //key to big number
    privateKey = BN_bin2bn(privateSignKey, privateSignKeyLength, NULL);
    publicKeyX = BN_bin2bn(publicSignKeyX, 0x20, NULL);
    publicKeyY = BN_bin2bn(publicSignKeyY, 0x20, NULL);
    //ec key
    key = EC_KEY_new_by_curve_name(curve);
    if (key == NULL) {
        bmLog(__FUNCTION__, "Create EC KEY failed");
        BN_free(privateKey);
        BN_free(publicKeyX);
        BN_free(publicKeyY);
        EC_POINT_free(publicKey);
        return 0;
    }

    //Set keys
    if (EC_KEY_set_private_key(key, privateKey) == 0) {
        bmLog(__FUNCTION__, "Set private key failed");
        BN_free(privateKey);
        BN_free(publicKeyX);
        BN_free(publicKeyY);
        EC_POINT_free(publicKey);
        EC_KEY_free(key);
        return 0;
    }
    group = EC_KEY_get0_group(key);
    publicKey = EC_POINT_new(group);
    if (EC_POINT_set_affine_coordinates_GFp(group, publicKey, publicKeyX, publicKeyY, 0) == 0) {
        bmLog(__FUNCTION__, "Set affine coordinates gfp failed");
        BN_free(privateKey);
        BN_free(publicKeyX);
        BN_free(publicKeyY);
        EC_POINT_free(publicKey);
        EC_KEY_free(key);
        return 0;
    }
    if (EC_KEY_set_public_key(key, publicKey) == 0) {
        bmLog(__FUNCTION__, "Set public key failed");
        BN_free(privateKey);
        BN_free(publicKeyX);
        BN_free(publicKeyY);
        EC_POINT_free(publicKey);
        EC_KEY_free(key);
        return 0;
    }
    if (EC_KEY_check_key(key) == 0) {
        ERR_print_errors_fp(stderr);
        bmLog(__FUNCTION__, "Check key failed");
        BN_free(privateKey);
        BN_free(publicKeyX);
        BN_free(publicKeyY);
        EC_POINT_free(publicKey);
        EC_KEY_free(key);
        return 0;
    }

    //Sign
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    if (EVP_DigestUpdate(ctx, buffer, bufferLength) == 0) {
        bmLog(__FUNCTION__, "EVP Digest update failed");
        BN_free(privateKey);
        BN_free(publicKeyX);
        BN_free(publicKeyY);
        EC_POINT_free(publicKey);
        EC_KEY_free(key);
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    EVP_DigestFinal_ex(ctx, digest, &digestLength);

    if (ECDSA_sign(0, digest, digestLength, result, &resultLength, key) != 1) {
        bmLog(__FUNCTION__, "ECDSA sign failed");
        BN_free(privateKey);
        BN_free(publicKeyX);
        BN_free(publicKeyY);
        EC_POINT_free(publicKey);
        EC_KEY_free(key);
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    if (ECDSA_verify(0, digest, digestLength, result, resultLength, key) != 1) {
        bmLog(__FUNCTION__, "ECDSA verify failed");
    }

    //Cleanup
    BN_free(privateKey);
    BN_free(publicKeyX);
    BN_free(publicKeyY);
    EC_POINT_free(publicKey);
    EC_KEY_free(key);
    EVP_MD_CTX_free(ctx);
    return resultLength;
}

int bmUtilsEncrypt(void* buffer, unsigned int bufferLength,
                   void* publicEncryptionKey, unsigned int publicEncryptionKeyLength,
                   void* result) {
    unsigned char publicEncryptionKeyX[0x20];
    unsigned char publicEncryptionKeyY[0x20];
    unsigned short curve;
    unsigned char generatePrivateKey[512] = { 0 };
    unsigned int generatePrivateKeyLength = 0;
    unsigned char generatePublicKeyX[512] = { 0 };
    unsigned int generatePublicKeyXLength = 0;
    unsigned char generatePublicKeyY[512] = { 0 };
    unsigned int generatePublicKeyYLength = 0;
    unsigned char generatePublicKey[512];
    unsigned int generatePublicKeyLength = 0;
    unsigned char ECDHKey[32] = { 0 };
    unsigned char ECDHKeySHA[512] = { 0 };
    unsigned int ECDHKeySHALength = 0;
    unsigned char keyE[512] = { 0 };
    unsigned char keyM[512] = { 0 };
    unsigned int keyMLength;
    unsigned char* p;
    unsigned char iv[16];
    EVP_CIPHER_CTX* ctx;
    unsigned char* encrypted;
    unsigned int encryptedLength;
    unsigned int temp;


    //Parameter check
    if (buffer == NULL || publicEncryptionKey == NULL || result == NULL) {
        bmLog(__FUNCTION__, "Invalid parameters!");
        return 0;
    }

    //Create keys
    memcpy(publicEncryptionKeyX, publicEncryptionKey + 1, 0x20);
    memcpy(publicEncryptionKeyY, publicEncryptionKey + publicEncryptionKeyLength - 0x20, 0x20);
    curve = 0x02ca;
    //Generate ECDH key
    generateKey(curve,
                generatePrivateKey, &generatePrivateKeyLength,
                generatePublicKeyX, &generatePublicKeyXLength,
                generatePublicKeyY, &generatePublicKeyYLength);
    generateECDHKey(curve,
                    publicEncryptionKeyX, publicEncryptionKeyY,
                    generatePrivateKey, generatePrivateKeyLength,
                    ECDHKey);

    //Calculate key_m and key_e
    ECDHKeySHALength = bmUtilsCalculateHash(ECDHKey, 32, ECDHKeySHA);
    memcpy(keyE, ECDHKeySHA, 32);
    keyMLength = ECDHKeySHALength - 32;
    memcpy(keyM, ECDHKeySHA + 32, keyMLength);
    //Build generated public key
    p = generatePublicKey;
    *(unsigned short*)p = htobe16(0x02ca);
    p += sizeof(unsigned short);
    *(unsigned short*)p = htobe16(generatePublicKeyXLength);
    p += sizeof(unsigned short);
    memcpy(p, generatePublicKeyX, generatePublicKeyXLength);
    p += generatePublicKeyXLength;
    *(unsigned short*)p = htobe16(generatePublicKeyYLength);
    p += sizeof(unsigned short);
    memcpy(p, generatePublicKeyY, generatePublicKeyYLength);
    p += generatePublicKeyYLength;
    generatePublicKeyLength = p - generatePublicKey;

    //Generate iv
    RAND_bytes(iv, 16);

    //Ciphering
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), 0, keyE, iv, 1);
    encryptedLength = 0;
    encrypted = (unsigned char*)malloc(bufferLength + 16 + 16);
    EVP_CipherUpdate(ctx, encrypted, &encryptedLength, buffer, bufferLength);
    EVP_CipherFinal_ex(ctx, encrypted + encryptedLength, &temp);
    encryptedLength += temp;

    //Write data to result
    p = result;
    memcpy(p, iv, 16);
    p += 16;
    memcpy(p, generatePublicKey, generatePublicKeyLength);
    p += generatePublicKeyLength;
    memcpy(p, encrypted, encryptedLength);
    p += encryptedLength;

    //Calculate hmac sha256
    HMAC(EVP_sha256(), keyM, keyMLength, result, p - (unsigned char*)result, p, &temp);
    p += temp;

    //Cleanup
    free(encrypted);
    EVP_CIPHER_CTX_free(ctx);

    return p - (unsigned char*)result;
}

unsigned long long bmUtilsPOW(void* payload, unsigned int payloadLength, unsigned int ttl) {
    unsigned long long target;
    unsigned char initialHash[512] = { 0 };
    unsigned int initialHashLength;
    unsigned char buffer[512] = { 0 };
    unsigned int bufferLength = 0;
    unsigned char output[512]  = { 0 };
    unsigned long long temp;
    unsigned long long* nonce;
    unsigned long long* hash;
    //Parameter check
    if (payload == NULL) {
        bmLog(__FUNCTION__, "Invalid parameter!");
        return 0;
    }
    //Calculate target
    target = bmUtilsCalculateTarget(payloadLength, ttl);
    //Calculate initialHash
    initialHashLength = bmUtilsCalculateHash(payload, payloadLength, initialHash);
    //Calculate POW
    temp = 0;
    hash = (unsigned long long*)output;
    nonce = (unsigned long long*)buffer;
    memcpy(buffer + sizeof(unsigned long long), initialHash, initialHashLength);
    bufferLength = sizeof(unsigned long long) + initialHashLength;
    while (1) {
        *nonce = htobe64(temp);
        bmUtilsCalculateDoubleHash(buffer, bufferLength, output);
        if (be64toh(*hash) < target) {
            return temp;
        } else {
            temp++;
        }
    }
}

//PRIVATE
void generateECDHKey(unsigned short curve,
                     void* x, void* y,
                     void* privateKey, unsigned int privateKeyLength,
                     void* result) {
    EC_KEY* otherKey;
    BIGNUM* otherPublicKeyX;
    BIGNUM* otherPublicKeyY;
    const EC_GROUP* otherGroup;
    EC_POINT* otherPublicKey;
    EC_KEY* ownKey;
    BIGNUM* ownPrivateKey;
    unsigned int resultLength;

    //Parameter check
    if (x == NULL || y == NULL || result == NULL) {
        bmLog(__FUNCTION__, "Invalid parameters!");
        return;
    }
    //Create other key
    otherKey = EC_KEY_new_by_curve_name(curve);
    if (otherKey == NULL) {
        bmLog(__FUNCTION__, "Create other key failed");
        return;
    }
    otherPublicKeyX = BN_bin2bn(x, 0x20, 0);
    otherPublicKeyY = BN_bin2bn(y, 0x20, 0);
    otherGroup = EC_KEY_get0_group(otherKey);
    otherPublicKey = EC_POINT_new(otherGroup);
    if (EC_POINT_set_affine_coordinates_GFp(otherGroup, otherPublicKey, otherPublicKeyX, otherPublicKeyY, 0) == 0) {
        bmLog(__FUNCTION__, "Set affine coordinates gfp failed");
        EC_POINT_free(otherPublicKey);
        BN_free(otherPublicKeyX);
        BN_free(otherPublicKeyY);
        EC_KEY_free(otherKey);
        return;
    }
    if (EC_KEY_set_public_key(otherKey, otherPublicKey) == 0) {
        bmLog(__FUNCTION__, "Set public key failed");
        EC_POINT_free(otherPublicKey);
        BN_free(otherPublicKeyX);
        BN_free(otherPublicKeyY);
        EC_KEY_free(otherKey);
        return;
    }
    if (EC_KEY_check_key(otherKey) == 0) {
        bmLog(__FUNCTION__, "Check key failed");
        EC_POINT_free(otherPublicKey);
        BN_free(otherPublicKeyX);
        BN_free(otherPublicKeyY);
        EC_KEY_free(otherKey);
        return;
    }
    //Create own key
    ownKey = EC_KEY_new_by_curve_name(curve);
    if (ownKey == NULL) {
        bmLog(__FUNCTION__, "create own key failed");
        EC_POINT_free(otherPublicKey);
        BN_free(otherPublicKeyX);
        BN_free(otherPublicKeyY);
        EC_KEY_free(otherKey);
    }
    ownPrivateKey = BN_bin2bn(privateKey, privateKeyLength, NULL);
    if (EC_KEY_set_private_key(ownKey, ownPrivateKey) == 0) {
        bmLog(__FUNCTION__, "set own private key failed");
        EC_POINT_free(otherPublicKey);
        BN_free(otherPublicKeyX);
        BN_free(otherPublicKeyY);
        EC_KEY_free(otherKey);
        EC_KEY_free(ownKey);
    }
    EC_KEY_set_method(ownKey, EC_KEY_OpenSSL());

    //Compute key
    resultLength = ECDH_compute_key(result, 32, otherPublicKey, ownKey, 0);
    if (resultLength != 32) {
        bmLog(__FUNCTION__, "ECDH key length error");
    }

    //Cleanup
    EC_POINT_free(otherPublicKey);
    BN_free(otherPublicKeyX);
    BN_free(otherPublicKeyY);
    EC_KEY_free(otherKey);
    EC_KEY_free(ownKey);
}

void generateKey(unsigned short curve,
                 void* privateKey, unsigned int* privateKeyLength,
                 void* publicKeyX, unsigned int* publicKeyXLength,
                 void* publicKeyY, unsigned int* publicKeyYLength) {
    EC_KEY* key;
    const BIGNUM* privateKeyBN;
    BIGNUM* publicKeyXBN;
    BIGNUM* publicKeyYBN;
    const EC_GROUP* group;
    const EC_POINT* publicKey;

    //Parameter check
    if (privateKey == NULL || publicKeyX == NULL || publicKeyY == NULL) {
        bmLog(__FUNCTION__, "Invalid parameters!");
        return;
    }
    //Generate key
    key = EC_KEY_new_by_curve_name(curve);
    if (EC_KEY_generate_key(key) == 0) {
        bmLog(__FUNCTION__, "Generate key failed");
        EC_KEY_free(key);
        return;
    }
    if (EC_KEY_check_key(key) == 0) {
        bmLog(__FUNCTION__, "Check own key failed");
        EC_KEY_free(key);
        return;
    }
    privateKeyBN = EC_KEY_get0_private_key(key);
    group = EC_KEY_get0_group(key);
    publicKey = EC_KEY_get0_public_key(key);
    publicKeyXBN = BN_new();
    publicKeyYBN = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(group, publicKey, publicKeyXBN, publicKeyYBN, 0) == 0) {
        bmLog(__FUNCTION__, "Get affine coordinates gfp failed");
        EC_KEY_free(key);
    }
    *privateKeyLength = BN_num_bytes(privateKeyBN);
    *publicKeyXLength = BN_num_bytes(publicKeyXBN);
    *publicKeyYLength = BN_num_bytes(publicKeyYBN);
    BN_bn2bin(privateKeyBN, privateKey);
    BN_bn2bin(publicKeyXBN, publicKeyX);
    BN_bn2bin(publicKeyYBN, publicKeyY);
    //Cleanup
    EC_KEY_free(key);
    BN_free(publicKeyXBN);
    BN_free(publicKeyYBN);
}

unsigned long long bmUtilsCalculateTarget(unsigned int length, unsigned int ttl) {
    BN_CTX* ctx;
    BIGNUM* target;
    BIGNUM* num_64;
    BIGNUM* num_temp;
    unsigned long long temp;

    temp = htobe64(1000 * (length + 8 + 1000 + ((ttl * (length + 8 + 1000)) / (1 << 16))));

    ctx = BN_CTX_new();
    target = BN_new();
    num_64 = BN_new();
    num_temp = BN_new();
    BN_set_word(target, 2);
    BN_set_word(num_64, 64);
    BN_bin2bn((unsigned char*)&temp, sizeof(unsigned long long), num_temp);
    BN_exp(target, target, num_64, ctx);
    BN_div(target, NULL, target, num_temp, ctx);
    BN_bn2bin(target, (unsigned char*)&temp);

    BN_free(num_64);
    BN_free(num_temp);
    BN_free(target);
    BN_CTX_free(ctx);

    return be64toh(temp);
}