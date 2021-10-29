#include "utils.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

#include "log.h"

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

    pubkeyBuffer = result;
    len =  i2o_ECPublicKey(k, &pubkeyBuffer);

    EC_POINT_free(pubkey);
    BN_free(privkey);
    EC_KEY_free(k);

    return len;
}

int bmUtilsSigning(void* buffer, unsigned int bufferLength, void* privateSignKey, unsigned int privateSignKeyLength, void* result) {
    unsigned char publicSignKey[512] = { 0 };
    unsigned int publicSignKeyLength = 0;
    unsigned char publicSignKeyX[0x20] = { 0 };
    unsigned char publicSignKeyY[0x20] = { 0 };
    unsigned char curve[2];
    BIGNUM* privateKey;
    BIGNUM* publicKeyX;
    BIGNUM* publicKeyY;
    EC_KEY* key;
    EC_GROUP* group;
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
    curve[0] = 0x02;
    curve[1] = 0xca;
    //key to big number
    privateKey = BN_bin2bn(privateSignKey, publicSignKeyLength, NULL);
    publicKeyX = BN_bin2bn(publicSignKeyX, 0x20, NULL);
    publicKeyY = BN_bin2bn(publicSignKeyY, 0x20, NULL);
    //ec key
    key = EC_KEY_new_by_curve_name(curve);
    if (key == NULL) {
        bmLog(__FUNCTION__, "Create EC KEY failed");
        BN_free(privateKey);
        BN_free(publicKeyX);
        BN_free(publicKeyY);
        EC_GROUP_free(group);
        EC_POINT_free(publicKey);
        return 0;
    }

    //Set keys
    if (EC_KEY_set_private_key(key, privateKey) == 0) {
        bmLog(__FUNCTION__, "Set private key failed");
        BN_free(privateKey);
        BN_free(publicKeyX);
        BN_free(publicKeyY);
        EC_GROUP_free(group);
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
        EC_GROUP_free(group);
        EC_POINT_free(publicKey);
        EC_KEY_free(key);
        return 0;
    }
    if (EC_KEY_set_public_key(key, publicKey) == 0) {
        bmLog(__FUNCTION__, "SEt public key failed");
        BN_free(privateKey);
        BN_free(publicKeyX);
        BN_free(publicKeyY);
        EC_GROUP_free(group);
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
        EC_GROUP_free(group);
        EC_POINT_free(publicKey);
        EC_KEY_free(key);
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    EVP_DigestFinal_ex(ctx, digest, &digestLength);
    ECDSA_sign(0, digest, digestLength, result, &resultLength, key);
    if (ECDSA_verify(0, digest, digestLength, result, resultLength, key) != 1) {
        bmLog(__FUNCTION__, "ECDSA verify failed");
    }
    //Cleanup
    BN_free(privateKey);
    BN_free(publicKeyX);
    BN_free(publicKeyY);
    EC_GROUP_free(group);
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
    unsigned char curve[2];

    //Parameter check
    if (buffer == NULL || publicEncryptionKey == NULL || result == NULL) {
        bmLog(__FUNCTION__, "Invalid parameters!");
        return 0;
    }

    //Create keys
    memcpy(publicEncryptionKeyX, publicEncryptionKey, 0x20);
    memcpy(publicEncryptionKeyY, publicEncryptionKey + 0x20, 0x20);
    curve[0] = 0x02;
    curve[1] = 0xca;


}