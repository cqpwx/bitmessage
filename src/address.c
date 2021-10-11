#include "address.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "log.h"
#include "protocol.h"

#define BM_ADDRESS_VERSION 4

/*
 * Description:
 *   Does an EC point multiplication; turns a private key into a public key.
 * Input:
 *  secret:private key
 *  result:public key
 * Return:
 *  pubkey size
 */
int pointMulti(unsigned char* secret, unsigned char* result);

/*
 * Description:
 *  Encode buffer into base58
 * Input:
 *  buffer:buffer to encode
 *  length:buffer length
 * Output:
 *  output:encode result
 * Return:
 *  length of output
 */
int encodeBase58(unsigned char* buffer, unsigned int length, unsigned char* output);

//PUBLIC
int bmAddressGenerateRandom(void* buffer) {
    unsigned char potentialPrivSigningKey[32] = { 0 };
    unsigned char potentialPubSigningKey[64] = { 0 };
    unsigned int potentialPubSigningKeyLength = 0;
    unsigned char tempBuffer[512] = { 0 };
    unsigned char tempBuffer2[512] = { 0 };
    unsigned char ripe[512] = { 0 };
    unsigned char potentialPrivEncryptionKey[32] = { 0 };
    unsigned char potentialPubEncryptionKey[64] = { 0 };
    unsigned int potentialPubEncryptionKeyLength = 0;
    EVP_MD_CTX* evp_ctx;
    unsigned int shaLength;
    unsigned int ripeLength;
    unsigned char* p;
    unsigned char storedBinaryData[512];
    unsigned int storedBinaryDataLength;
    unsigned int tempLength;
    unsigned int tempLength2;

    //Parameter check
    if (buffer == NULL) {
        bmLog(__FUNCTION__, "Invalid parameter!");
        return 0;
    }
    //Create random ripe
    while (RAND_bytes(potentialPrivSigningKey, 32) != 1) {
        sleep(1);
        memset(potentialPrivSigningKey, 0, 32);
    }
    potentialPubSigningKeyLength = pointMulti(potentialPrivSigningKey, potentialPubSigningKey);
    while (1) {
        memset(potentialPrivEncryptionKey, 0, 32);
        while (RAND_bytes(potentialPrivEncryptionKey, 32) != 1) {
            sleep(1);
            memset(potentialPrivEncryptionKey, 0, 32);
        }
        potentialPubEncryptionKeyLength = pointMulti(potentialPrivEncryptionKey, potentialPubEncryptionKey);
        memset(tempBuffer, 0, 512);
        memset(tempBuffer2, 0, 512);
        memcpy(tempBuffer, potentialPubSigningKey, potentialPubSigningKeyLength);
        memcpy(tempBuffer + potentialPubSigningKeyLength,
               potentialPubEncryptionKey,
               potentialPubEncryptionKeyLength);
        evp_ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(evp_ctx, EVP_sha512(), NULL);
        EVP_DigestUpdate(evp_ctx, tempBuffer, potentialPubSigningKeyLength + potentialPubEncryptionKeyLength);
        EVP_DigestFinal_ex(evp_ctx, tempBuffer2, &shaLength);
        EVP_MD_CTX_free(evp_ctx);
        evp_ctx = NULL;
        evp_ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(evp_ctx, EVP_ripemd160(), NULL);
        EVP_DigestUpdate(evp_ctx, tempBuffer2, shaLength);
        EVP_DigestFinal_ex(evp_ctx, ripe, &ripeLength);
        EVP_MD_CTX_free(evp_ctx);
        evp_ctx = NULL;
        if (ripe[0] == 0) {
            break;
        }
    }
    //Encode address
    memset(storedBinaryData, 0, 512);
    p = storedBinaryData;
    p += bmWriteVarint(BM_ADDRESS_VERSION, p);
    p += bmWriteVarint(1, p);
    memcpy(p, ripe + 1, ripeLength - 1);
    p += ripeLength - 1;
    storedBinaryDataLength = p - storedBinaryData;
    evp_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(evp_ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(evp_ctx, storedBinaryData, storedBinaryDataLength);
    EVP_DigestFinal_ex(evp_ctx, tempBuffer, &tempLength);
    EVP_MD_CTX_free(evp_ctx);
    evp_ctx = NULL;
    memset(tempBuffer, 0, 512);
    evp_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(evp_ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(evp_ctx, tempBuffer, tempLength);
    EVP_DigestFinal_ex(evp_ctx, tempBuffer2, &tempLength2);
    EVP_MD_CTX_free(evp_ctx);
    evp_ctx = NULL;

    memset(tempBuffer, 0, 512);
    memcpy(tempBuffer, storedBinaryData, storedBinaryDataLength);
    memcpy(tempBuffer + storedBinaryDataLength, tempBuffer2, 4);

    return encodeBase58(tempBuffer, storedBinaryDataLength + 4, buffer);
}

//PRIVATE
int pointMulti(unsigned char* secret, unsigned char* result) {
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

const char alphabet[] =  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
int encodeBase58(unsigned char* buffer, unsigned int length, unsigned char* output) {
    BN_CTX* ctx;
    BIGNUM* input;
    BIGNUM* zero;
    BIGNUM* base;
    BIGNUM* rem;
    unsigned int count;
    unsigned int i;
    unsigned char temp;

    //Parameter check
    if (buffer == NULL || output == NULL) {
        bmLog(__FUNCTION__, "Invalid parameter!");
        return 0;
    }
    //Init ctx
    ctx = BN_CTX_new();
    //Init zero
    zero = BN_new();
    BN_zero(zero);
    //Init base
    base = BN_new();
    BN_set_word(base, strlen(alphabet));
    //Init rem
    rem = BN_new();
    BN_zero(rem);
    //Init input
    input = BN_bin2bn(buffer, length, NULL);

    //Check if input is zero
    if (BN_cmp(input, zero) == 0) {
        output[0] = alphabet[0];
        return 1;
    }
    //Calculate
    count = 0;
    while (BN_cmp(input, zero)) {
        BN_div(input, rem, input, base, ctx);
        output[count++] = alphabet[BN_get_word(rem)];
    }
    //reverse
    for (i = 0; i < count / 2; i++) {
        temp = output[i];
        output[i] = output[count - 1 - i];
        output[count - 1 - i] = temp;
    }
    //end
    return count;
}