#include "address.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "log.h"
#include "protocol.h"
#include "inv.h"
#include "utils.h"

#define BM_ADDRESS_VERSION 4

extern struct BMInv* BM_GLOBAL_INV;

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

/*
 * Description:
 *  encode bitmessage address
 * Input:
 *  ripe:address ripe
 *  ripeLength:address ripe length
 * Output:
 *  result:address
 * Return:
 *  result length
 */
int encodeAddress(void* ripe, unsigned int ripeLength, unsigned char* result);

/* Description:
 *  store address object to inv
 * Input:
 */
void storeToInv();

//PUBLIC
int bmAddressGenerateRandom(void* buffer) {
    unsigned char potentialPrivSigningKey[32] = { 0 };
    unsigned char potentialPubSigningKey[64] = { 0 };
    unsigned int potentialPubSigningKeyLength = 0;
    unsigned char potentialPrivEncryptionKey[32] = { 0 };
    unsigned char potentialPubEncryptionKey[64] = { 0 };
    unsigned int potentialPubEncryptionKeyLength = 0;
    unsigned char tempBuffer[512] = { 0 };
    unsigned int tempLength;
    unsigned char tempBuffer2[512] = { 0 };
    unsigned int tempLength2;
    unsigned char ripe[512] = { 0 };
    unsigned int shaLength;
    unsigned int ripeLength;
    EVP_MD_CTX* evp_ctx;
    unsigned char* p;

    int addressLength;

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
    potentialPubSigningKeyLength = bmUtilsPointMulti(potentialPrivSigningKey, potentialPubSigningKey);
    while (1) {
        memset(potentialPrivEncryptionKey, 0, 32);
        while (RAND_bytes(potentialPrivEncryptionKey, 32) != 1) {
            sleep(1);
            memset(potentialPrivEncryptionKey, 0, 32);
        }
        potentialPubEncryptionKeyLength = bmUtilsPointMulti(potentialPrivEncryptionKey, potentialPubEncryptionKey);
        memset(tempBuffer, 0, 512);
        memset(tempBuffer2, 0, 512);
        memcpy(tempBuffer, potentialPubSigningKey, potentialPubSigningKeyLength);
        memcpy(tempBuffer + potentialPubSigningKeyLength,
               potentialPubEncryptionKey,
               potentialPubEncryptionKeyLength);
        shaLength = bmUtilsCalculateHash(tempBuffer, potentialPubSigningKeyLength + potentialPubEncryptionKeyLength, tempBuffer2);
        ripeLength = bmUtilsCalculateRipeHash(tempBuffer2, shaLength, ripe);
        if (ripe[0] == 0) {
            break;
        }
    }

    //encode address
    addressLength = encodeAddress(ripe, ripeLength, buffer);

    //Store address to inv list
    storeToInv();

    return addressLength;
}

//PRIVATE
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

int encodeAddress(void* ripe, unsigned int ripeLength, unsigned char* result) {
    unsigned char storedBinaryData[512] = { 0 };
    unsigned int storedBinaryDataLength;
    unsigned char storedBinaryDataDoubleHash[512] = { 0 };
    unsigned char tempBuffer[512] = { 0 };
    unsigned int tempLength;
    unsigned char* p;
    unsigned int addressLength;


    //Parameter check
    if (ripe == NULL || result == NULL) {
        bmLog(__FUNCTION__, "Invalid parameter!");
        return 0;
    }


    //Encode address
    p = storedBinaryData;
    p += bmWriteVarint(BM_ADDRESS_VERSION, p);
    p += bmWriteVarint(1, p);
    memcpy(p, ripe + 1, ripeLength - 1);
    p += ripeLength - 1;

    storedBinaryDataLength = p - storedBinaryData;
    bmUtilsCalculateDoubleHash(storedBinaryData, storedBinaryDataLength, storedBinaryDataDoubleHash);

    memcpy(tempBuffer, storedBinaryData, storedBinaryDataLength);
    memcpy(tempBuffer + storedBinaryDataLength, storedBinaryDataDoubleHash, 4);
    addressLength = encodeBase58(tempBuffer, storedBinaryDataLength + 4, result);

    return addressLength;
}

void storeToInv(void* ripe, unsigned int ripeLength,
                void* publicSigningKey, unsigned int publicSigningKeyLength,
                void* publicEncryptionKey, unsigned int publicEncryptionKeyLength,
                void* privateSigningKey, unsigned int privateSigningKeyLength) {
    unsigned char addressData[512] = { 0 };
    unsigned int addressDataLength;
    unsigned char addressDataDoubleHash[512] = { 0 };
    unsigned int addressDataDoubleHashLength;
    unsigned char dataBuffer[512] = { 0 };
    unsigned int dataLength;
    unsigned char tempBuffer[1024] = { 0 };
    unsigned int tempLength;
    int ttl;
    int embeddedTime;
    unsigned char* payload;
    unsigned char* p;
    unsigned char* q;
    unsigned char signature[512];
    unsigned int signatureLength;
    unsigned long long nonce;
    unsigned char inv[BM_INV_SIZE];

    //Calculate double hash of address data
    p = addressData;
    p += bmWriteVarint(BM_ADDRESS_VERSION, p);
    p += bmWriteVarint(1, p);
    memcpy(p, ripe + 1, ripeLength - 1);
    p += ripeLength - 1;
    addressDataLength = p - addressData;
    addressDataDoubleHashLength = bmUtilsCalculateDoubleHash(addressData,
                                                                  addressDataLength,
                                                                  addressDataDoubleHash);

    //Build payload
    srand(time(NULL));
    ttl = 28 * 24 * 60 * 60 + (rand() % 300);
    embeddedTime = time(NULL) + ttl;
    payload = (unsigned char*)malloc(512);
    p = (unsigned char*)payload + sizeof(unsigned long long);
    *(uint64_t*)p = htobe64(embeddedTime);
    p += sizeof(uint64_t);
    *(uint32_t*)p = htobe32(1);
    p += sizeof(uint32_t);
    p += bmWriteVarint(BM_ADDRESS_VERSION, p);
    p += bmWriteVarint(1, p);
    memcpy(p, addressDataDoubleHash + 32, addressDataDoubleHashLength - 32);
    p += addressDataDoubleHashLength - 32;
    //Build data
    q = dataBuffer;
    *(uint32_t*)q = htobe32(0);//bitfiled
    q += sizeof(uint32_t);
    memcpy(q, publicSigningKey, publicSigningKeyLength);//publicSigningKey
    q += publicSigningKeyLength;
    memcpy(q, publicEncryptionKey, publicEncryptionKeyLength);//publicEncryptionKey
    q += publicEncryptionKeyLength;
    q += bmWriteVarint(1000, q);//noncetrialsperbyte
    q += bmWriteVarint(1000, q);//payloadlengthextrabytes
    //Signing
    memcpy(tempBuffer, payload + sizeof(unsigned long long), p - payload + sizeof(unsigned long long));
    tempLength += (p - payload + sizeof(unsigned long long));
    memcpy(tempBuffer + tempLength, dataBuffer, q - dataBuffer);
    tempLength += (q - dataBuffer);
    signatureLength = bmUtilsSigning(tempBuffer, tempLength,
                                     privateSigningKey, privateSigningKeyLength,
                                     signature);
    q += bmWriteVarint(signatureLength, q);
    memcpy(q, signature, signatureLength);
    q += signatureLength;
    //Encryption
    p += bmUtilsEncrypt(dataBuffer, q - dataBuffer,
                        publicEncryptionKey, publicEncryptionKeyLength,
                        p);
    //Do POW for this public key message
    nonce = bmUtilsPOW(payload + sizeof(unsigned long long),
                       p - payload + sizeof(unsigned long long),
                       ttl);
    *(unsigned long long*)payload = htobe64(nonce);

    //Add to inv
    bmInvCalculate(payload, p - payload, inv);
    bmInvInsertNodeWithObject(BM_GLOBAL_INV, inv, payload);
}