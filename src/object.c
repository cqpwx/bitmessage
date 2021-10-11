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
	uint64_t nonceTrialsPerByte = 1000;
	uint64_t payloadLengthExtraBytes = 1000;
	uint8_t mdFirst[64] = {0};
	uint32_t mdFirstLength = 0;
	uint8_t tempBuffer[128] = {0};
	uint8_t mdSecond[64] = {0};
	uint32_t mdSecondLength = 0;
	EVP_MD_CTX* mdctx;
	uint64_t pow;
	BN_CTX* bnctx;
	BIGNUM* a;
	BIGNUM* b;
	BIGNUM* c;
	BIGNUM* d;
	BIGNUM* e;
	BIGNUM* f;
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
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
	EVP_DigestUpdate(mdctx, p + 8, payloadLength - 8);
	EVP_DigestFinal_ex(mdctx, mdFirst, &mdFirstLength);
	EVP_MD_CTX_free(mdctx);
	mdctx = NULL;
	memcpy(tempBuffer, payload, 8);
	memcpy(tempBuffer + 8, mdFirst, mdFirstLength);
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
	EVP_DigestUpdate(mdctx, tempBuffer, mdFirstLength + 8);
	EVP_DigestFinal_ex(mdctx, mdSecond, &mdSecondLength);
	EVP_MD_CTX_free(mdctx);
	mdctx = NULL;
	pow = be64toh(*(uint64_t*)mdSecond);
	//Compare
	bnctx = BN_CTX_new();
	a = BN_new();
	b = BN_new();
	c = BN_new();
	d = BN_new();
	e = BN_new();
	f = BN_new();
	BN_set_word(a, 2);
	BN_set_word(b, 64);
	if (!BN_exp(c, a, b, bnctx)) {
		bmLog(__FUNCTION__, "failed to calculate 2^64");
		return 0;
	}
	BN_set_word(d, nonceTrialsPerByte * (payloadLength + payloadLengthExtraBytes + ((ttl * (payloadLength + payloadLengthExtraBytes)) / 65535u)));
	if (!BN_div(e, f, c, d, bnctx)) {
		bmLog(__FUNCTION__, "failed to calculate target");
	}
	target = BN_get_word(e);
	BN_free(a);
	BN_free(b);
	BN_free(c);
	BN_free(d);
	BN_free(e);
	BN_free(f);
	BN_CTX_free(bnctx);
	return pow <= target;
}