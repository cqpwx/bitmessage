#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define BM_NODE_NETWORK			1
#define BM_NODE_SSL				2
#define BM_NODE_DANDELION		8

#define BM_STATUS_WARNING		0
#define BM_STATUS_ERROR			1
#define BM_STATUS_FATAL			2

#define BM_OBJECT_GETPUBKEY		0
#define BM_OBJECT_PUBKEY		1
#define BM_OBJECT_MSG			2
#define BM_OBJECT_BROADCAST		3
#define BM_OBJECT_ONIONPEER		0x746f72
#define BM_OBJECT_I2P			0x493250
#define BM_OBJECT_ADDR			0x61646472

#define BM_MAGIC 0xE9BEB4D9

#define BM_INV_SIZE 32

struct BMHeader {
	uint32_t magic;
	uint8_t command[12];
	uint32_t payloadLength;
	unsigned char checksum[4];
} __attribute__((packed));


struct BMNetAddress {
	uint64_t time;
	uint32_t stream;
	uint64_t services;
	uint8_t ip[16];
	uint16_t port;
} __attribute__((packed));

/*
* Description:
*	Write varint to buffer
* Input:
*	data:Input data
* Output:
*	buffer:Buffer to write
* Return:
*	Bytes write
*/
int bmWriteVarint(uint64_t data, void* buffer);

/*
* Description:
*	Write varint to buffer
* Input:
*	buffer:Buffer to read
* Output:
*	data: data read
* Return:
*	Bytes read
*/
int bmReadVarint(void* buffer, uint64_t* data);

/*
* Description:
*	Create bitmessage network packet
* Input:
*	command:Packet command
*	payload:Packet payload
*	payloadLength:The length of payload
* Output:
*	result:The created packet buffer
* Return:
*	Created packet buffer length
*/
int bmCreatePacket(const char* command, void* payload, uint32_t payloadLength, void** result);

/*
* Description:
*	Create version payload
* Input:
*	remoteHost:Remote host IP
*	remotePort:Remote host port
* Output:
*	result:Created version packet buffer
* Return:
*	packet length
*/
int bmCreateVersionPayload(const char* remoteHost, int remotePort, void** result);


/*
* Description:
*	Check if the checksum is right.
* Input:
*	payload:Payload to check
*	length:Payload length
*	checksum:Header checksum
* Return:
*	0 if wrong,1 if right
*/
int bmCheckChecksum(void* payload, int length, unsigned char* checksum);

#endif