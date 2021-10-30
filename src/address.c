#include "address.h"

#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/ec.h>

#include "log.h"
#include "protocol.h"
#include "inv.h"
#include "utils.h"

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
    unsigned char tempBuffer2[512] = { 0 };
    unsigned char ripe[512] = { 0 };
    unsigned int shaLength;
    unsigned int ripeLength;
    struct BMObject* pubkeyObject;
    int addressLength;
    unsigned char inv[BM_INV_SIZE];

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
    //Add to inv
    pubkeyObject = bmObjectCreatePubkey(ripe, ripeLength,
                                        potentialPubSigningKey, potentialPubSigningKeyLength,
                                        potentialPubEncryptionKey, potentialPubEncryptionKeyLength,
                                        potentialPrivEncryptionKey, 32);
    bmInvInsertNodeWithObject(BM_GLOBAL_INV, pubkeyObject);

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