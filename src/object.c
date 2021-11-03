#include "object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "log.h"
#include "object.h"
#include "protocol.h"
#include "utils.h"

struct BMObjectHeader {
	uint64_t nonce;
	uint64_t expiresTime;
	uint32_t objectType;
} __attribute__((packed));

/*
 * Description:
 *  isProofOfWorkSufficient
 * Input:
 *	payload:payload buffer
 *	payloadLength:payload length
 * Return:
 *	1 if ok, or 0
 */
int isProofOfWorkSufficient(void* payload, uint64_t payloadLength);

//PUBLIC
int bmObjectHandle(uint8_t* payload, uint64_t payloadLength) {
	struct BMObjectHeader* header;
	uint8_t* p;
	uint64_t version;
	uint64_t streamNumber;
	uint32_t objectType;

	//Parameters check
	if (payload == NULL || payloadLength == 0) {
		bmLog(__FUNCTION__, "Invalid parameter!");
		return 0;
	}
	//Check nonce
	if (isProofOfWorkSufficient(payload, payloadLength) == 0) {
		bmLog(__FUNCTION__, "Invalid nonce!");
		return 0;
	}
	//Read header
	p = payload;
	header = (struct BMObjectHeader*)payload;
	p += sizeof(struct BMObjectHeader);
	//Read version
	p += bmReadVarint(p, &version);
	bmLog(__FUNCTION__, "Version:%lu", version);
	//Read stream number
	p += bmReadVarint(p, &streamNumber);
	bmLog(__FUNCTION__, "StreamNumber:%lu", streamNumber);
	//Handle object
	objectType = ntohl(header->objectType);
	switch (objectType) {
		case BM_OBJECT_GETPUBKEY:
			bmLog(__FUNCTION__, "getpubkey");
			break;
		case BM_OBJECT_PUBKEY:
			bmLog(__FUNCTION__, "pubkey");
			break;
		case BM_OBJECT_MSG:
			bmLog(__FUNCTION__, "msg");
			break;
		case BM_OBJECT_BROADCAST:
			bmLog(__FUNCTION__, "broadcast");
			break;
		case BM_OBJECT_ONIONPEER:
			bmLog(__FUNCTION__, "onionpeer");
			break;
		case BM_OBJECT_I2P:
			bmLog(__FUNCTION__, "i2p");
			break;
		case BM_OBJECT_ADDR:
			bmLog(__FUNCTION__, "addr");
			break;
		default:
			bmLog(__FUNCTION__, "Unknown object received type=%x", objectType);
	}
	return 1;
}

struct BMObject* bmObjectCreatePubkey(struct BMAddress* address) {
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
    struct BMObject* result;

    //Calculate double hash of address data
    p = addressData;
    p += bmWriteVarint(BM_ADDRESS_VERSION, p);
    p += bmWriteVarint(1, p);
    memcpy(p, address->ripe + 1, address->ripeLength - 1);
    p += address->ripeLength - 1;
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
    memcpy(q, address->publicSignKey, address->publicSignKeyLength);//publicSigningKey
    q += address->publicSignKeyLength;
    memcpy(q, address->publicEncryptionKey, address->publicEncryptionKeyLength);//publicEncryptionKey
    q += address->publicEncryptionKeyLength;
    q += bmWriteVarint(1000, q);//noncetrialsperbyte
    q += bmWriteVarint(1000, q);//payloadlengthextrabytes
    //Signing
    memcpy(tempBuffer, payload + sizeof(unsigned long long), p - payload + sizeof(unsigned long long));
    tempLength += (p - payload + sizeof(unsigned long long));
    memcpy(tempBuffer + tempLength, dataBuffer, q - dataBuffer);
    tempLength += (q - dataBuffer);
    signatureLength = bmUtilsSigning(tempBuffer, tempLength,
                                     address->privateSignKey, 32,
                                     signature);
    q += bmWriteVarint(signatureLength, q);
    memcpy(q, signature, signatureLength);
    q += signatureLength;
    //Encryption
    p += bmUtilsEncrypt(dataBuffer, q - dataBuffer,
                        address->publicEncryptionKey, address->publicEncryptionKeyLength,
                        p);
    //Do POW for this public key message
    nonce = bmUtilsPOW(payload + sizeof(unsigned long long),
                       p - payload + sizeof(unsigned long long),
                       ttl);
    *(unsigned long long*)payload = htobe64(nonce);

    //Setup result
    result = (struct BMObject*)malloc(sizeof(struct BMObject));
    result->payload = payload;
    result->payloadLength = p - payload;
    result->objectType = BM_OBJECT_PUBKEY;
    result->streamNumber = 1;
    result->embeddedTime = embeddedTime;
    bmInvCalculate(result->payload, result->payloadLength, result->inv);

    return result;
}

//PIRVATE
int isProofOfWorkSufficient(void* payload, uint64_t payloadLength) {
	struct BMObjectHeader* header;
	uint8_t* p;
	uint64_t expiresTime;
	uint64_t ttl;
	uint8_t mdFirst[128] = {0};
	uint32_t mdFirstLength = 0;
	uint8_t tempBuffer[128] = {0};
	uint8_t mdSecond[128] = {0};
	uint64_t pow;
	uint64_t target;

	p = (uint8_t*)payload;
	header = (struct BMObjectHeader*)p;
	expiresTime = be64toh(header->expiresTime);
	//Calculate the TTL
	ttl = expiresTime - time(NULL);
	if (ttl < 300) {
		ttl = 300;
	}
	//Calclulate the POW
    mdFirstLength = bmUtilsCalculateHash(p + 8, payloadLength - 8, mdFirst);
	memcpy(tempBuffer, p, 8);
	memcpy(tempBuffer + 8, mdFirst, mdFirstLength);
    bmUtilsCalculateDoubleHash(tempBuffer, mdFirstLength + 8, mdSecond);
	pow = be64toh(*(uint64_t*)mdSecond);
	//Compare
    target = bmUtilsCalculateTarget(payloadLength, ttl);
	return pow <= target;
}