#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <endian.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

#include "log.h"

#define USER_AGENT "libbm"


int bmWriteVarint(uint64_t data, void* buffer) {
	unsigned char* p;

	if (buffer == NULL) {
		bmLog(__FUNCTION__, "NULL buffer input!\n");
		return 0;
	}
	p = (unsigned char*)buffer;

	if (data < 253) {
		*p = (unsigned char)data;
		return sizeof(unsigned char);
	}
	if (data >= 253 && data < 65535) {
		*p = 253;
		*(uint16_t*)(p + 1) = htons((uint16_t)data);
		return sizeof(uint16_t);
	}
	if (data >= 65535 && data < 4294967296) {
		*p = 254;
		*(uint32_t*)(p + 1) = htonl((uint32_t)data);
		return sizeof(uint32_t);
	}
	if (data >= 4294967296) {
		*p = 255;
		*(uint64_t*)(p + 1) = htobe64(data);
	}

	return 0;
}

int bmReadVarint(void* buffer, uint64_t* data) {
	unsigned char* p;
	unsigned char mark = 0;

	if (buffer == NULL) {
		bmLog(__FUNCTION__, "NULL Buffer input\n");
		return 0;
	}
	if (data == NULL) {
		bmLog(__FUNCTION__, "NULL data pointer input\n");
		return 0;
	}
	p = (unsigned char*)buffer;
	mark = *(p++);
	if (mark < 253) {
		*data = mark;
		return sizeof(unsigned char);
	}
	if (mark == 253) {
		*data = ntohs(*(uint16_t*)p);
		return sizeof(uint16_t);
	}
	if (mark == 254) {
		*data = ntohl(*(uint32_t*)p);
		return sizeof(uint32_t);
	}
	if (mark == 255) {
		*data = be64toh(*(uint64_t*)p);
		return sizeof(uint64_t);
	}
	return 0;
}

int bmCreatePacket(const char* command, void* payload, uint32_t payloadLength, void** result) {
	struct BMHeader* header;
	int packetLength;
	int commandLength;
	unsigned char checksum[1024] = { 0 };
	unsigned int checksumLength = 0;
	EVP_MD_CTX* mdctx;

	packetLength = sizeof(struct BMHeader) + payloadLength;
	*result = malloc(packetLength);
	if (*result == NULL) {
		bmLog(__FUNCTION__, "Failed to malloc packet!\n");
		return -1;
	}
	memset(*result, 0, packetLength);
	//Setup Header
	header = (struct BMHeader*)*result;
	//Magic
	header->magic = htonl(BM_MAGIC);
	//Command
	commandLength = strlen(command);
	if (commandLength >= 12) {
		memcpy(header->command, command, 12);
	} else {
		memcpy(header->command, command, commandLength);
	}
	//Payload Length
	header->payloadLength = htonl(payloadLength);
	//Checksum
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
	EVP_DigestUpdate(mdctx, payload, payloadLength);
	EVP_DigestFinal_ex(mdctx, checksum, &checksumLength);
	EVP_MD_CTX_free(mdctx);
	mdctx = NULL;
	memcpy(header->checksum, checksum, 4);
	//Setup Payload
	if (payload != NULL) {
		memcpy((void*)((unsigned char*)*result + sizeof(struct BMHeader)), payload, payloadLength);
	}
	//The end
	return packetLength;
}

int bmCreateVersionPayload(const char* remoteHost, int remotePort, void** result) {
	int len = 0;
	char* p;
	int i;
	unsigned int userAgentLength;
	uint64_t random;


	*result = malloc(128);

	if (*result == NULL) {
		bmLog(__FUNCTION__, "Failed to malloc version packet!\n");
		return len;
	}

	memset(*result, 0, 128);

	p = (char*)*result;

	//Protocol version
	*(uint32_t*)(p + len) = htonl(3);
	len += sizeof(uint32_t);
	//Services
	*(long long*)(p + len) = htobe64(BM_NODE_NETWORK);
	len += sizeof(long long);
	//Timestamp
	*(long long*)(p + len) = htobe64(time(NULL));
	len += sizeof(long long);
	//Service
	*(uint64_t*)(p + len) = htobe64(1);
	len += sizeof(uint64_t);
	//Remote host
	for (i = 0; i < 10; i++) {
		p[len++] = 0;
	}
	for (i = 0; i < 2; i++) {
		p[len++] = 0xff;
	}
	inet_pton(AF_INET, remoteHost, p + len);
	len += 4;
	//Remote port
	*(uint16_t*)(p + len) = htons(remotePort);
	len += sizeof(uint16_t);
	//Service
	*(uint64_t*)(p + len) = htobe64(1);
	len += sizeof(uint64_t);
	//Local host
	for (i = 0; i < 10; i++) {
		p[len++] = 0;
	}
	for (i = 0; i < 2; i++) {
		p[len++] = 0xff;
	}
	*(uint32_t*)(p + len) = htonl(2130706433);
	len += sizeof(uint32_t);
	//Local port
	*(uint16_t*)(p + len) = htons(8444);
	len += sizeof(uint16_t);
	//Nonce
	srand(time(NULL));
	random = 18446744073709551614u * (rand() / (double)RAND_MAX);
	*(uint64_t*)(p + len) = htobe64(random);
	len += sizeof(uint64_t);
	//UserAgent
	userAgentLength = strlen(USER_AGENT);
	len += bmWriteVarint(userAgentLength, p + len);
	memcpy(p + len, USER_AGENT, userAgentLength);
	len += userAgentLength + 1;
	//Streams
	len += bmWriteVarint(1, p + len);//Count
	len += bmWriteVarint(1, p + len);//Only stream 1 used
	//The end
	return len;
}

int bmCheckChecksum(void* payload, int length, unsigned char* checksum) {
	EVP_MD_CTX* mdctx;
	unsigned char checksumBuffer[1024] = { 0 };
	unsigned int checksumLength = 0;
	
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
	EVP_DigestUpdate(mdctx, payload, length);
	EVP_DigestFinal_ex(mdctx, checksumBuffer, &checksumLength);
	EVP_MD_CTX_free(mdctx);
	mdctx = NULL;
	if (memcmp(checksum, checksumBuffer, 4) == 0) {
		return 1;
	}
	return 0;
}
