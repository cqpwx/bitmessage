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
*	payload:payload buffer
* Return:
*	1 if ok, or 0
*/
int checkNonce(void* payload, uint64_t payloadLength);

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
	if (checkNonce(payload, payloadLength)) {
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

//PIRVATE
int checkNonce(void* payload, uint64_t payloadLength) {
	struct BMObjectHeader* header;
	uint8_t* p;
	uint64_t expiresTime;
	uint64_t ttl;
	uint8_t mdFirst[64] = {0};
	uint32_t mdFirstLength = 0;
	uint8_t tempBuffer[128] = {0};
	uint8_t mdSecond[64] = {0};
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
	memcpy(tempBuffer, payload, 8);
	memcpy(tempBuffer + 8, mdFirst, mdFirstLength);
    bmUtilsCalculateHash(tempBuffer, mdFirstLength + 8, mdSecond);
	pow = be64toh(*(uint64_t*)mdSecond);
	//Compare
    target = bmUtilsCalculateTarget(payloadLength, ttl);
	return pow <= target;
}