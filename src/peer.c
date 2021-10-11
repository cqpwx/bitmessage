#include "peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include "log.h"
#include "object.h"

/*
* Description:
*	Connect to a bitmessage peer
* Input:
*	peer:Peer struct
*/
void connectHost(struct BMPeer* peer);

/*
* Description:
*	First handshake with bitmessage peer
*  Input:
*	peer:Peer to connect
*/
void firstHandshake(struct BMPeer* peer);

/*
* Description:
*	Send version packet to peer
* Input:
*	peer:Peer to send
*/
void sendVersion(struct BMPeer* peer);

/*
* Description:
*	Send verack packet to peer
* Input:
*	peer:Peer to send
*/
void sendVerack(struct BMPeer* peer);

/*
* Description:
*	Receive packet from peer
* Input:
*	peer:Peer to recieve
* Output:
*	header:Header buffer to receive packet header
*	payload:Payload buffer pointer
*/
void recvPacket(struct BMPeer* peer, struct BMHeader* header, void** payload);

/*
* Description:
*	Listen on peer
* Input:
*	peer:Peer to listen
*/
void listenSocket(struct BMPeer* peer);

/*
* Description:
*	Process incoming packet from peer
* Input:
*	peer:Peer to handle
*	header:packet header buffer
*	payload:Payload buffer
*/
void processPacket(struct BMPeer* peer, struct BMHeader* header, void* payload);

//THREAD
void* listenThread(void* data);

//EXTERN
extern struct BMInv* BM_GLOBAL_INV;

//PUBLIC
struct BMPeerList* bmPeersCreate() {
	struct BMPeerList* result;

	result = (struct BMPeerList*)malloc(sizeof(struct BMPeerList));
	if (result == NULL) {
		bmLog(__FUNCTION__, "Failed to malloc!");
		return NULL;
	}
	memset(result, 0, sizeof(struct BMPeerList));

	return result;
}

int bmPeersAdd(struct BMPeerList* list, struct BMPeer* peer) {
	struct BMPeerNode* node;

	if (list == NULL || peer == NULL) {
		bmLog(__FUNCTION__, "Invalid parameters!");
		return 0;
	}
	if (list->count == 0) {
		list->data = (struct BMPeerNode*)malloc(sizeof(struct BMPeerNode));
		node = list->data;
	} else {
		node = list->data;
		while (node->next) {
			node = node->next;
		}
		node->next = (struct BMPeerNode*)malloc(sizeof(struct BMPeerNode));
		node = node->next;
	}
	if (node == NULL) {
		bmLog(__FUNCTION__, "Failed to malloc!");
		return 0;
	}
	memset(node, 0, sizeof(struct BMPeerNode));
	node->peer = peer;
	return 1;
}

struct BMPeer* bmPeerCreate(const char* host, unsigned short port) {
	struct BMPeer* peer;

	//Parameter check
	if (host == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter!");
		return NULL;
	}
	//Create peer struct
	peer = (struct BMPeer*)malloc(sizeof(struct BMPeer));
	if (peer == NULL) {
		bmLog(__FUNCTION__, "Failed to malloc!");
		return NULL;
	}
	memset(peer, 0, sizeof(struct BMPeer));
	//Set IP and port
	peer->host = strdup(host);
	peer->port = port;
	//Connect
	connectHost(peer);
	//Handshake
	firstHandshake(peer);
	//Create listening thread
	if (pthread_create(&peer->thread, NULL, listenThread, (void*)peer)) {
		bmLog(__FUNCTION__, "Failed to create listen thread!");
		close(peer->sock);
		free(peer->host);
		free(peer);
		return NULL;
	}

	bmLog(__FUNCTION__, "Connection established!");
	return peer;
}

void bmPeerAddGetdata(struct BMPeer* peer, uint8_t* inv) {
	struct BMGetdata* node;

	//Parameter check
	if (peer == NULL || inv == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter!");
		return;
	}
	//Insert node
	if (peer->getdata == NULL) {
		peer->getdata = (struct BMGetdata*)malloc(sizeof(struct BMGetdata));
		node = peer->getdata;
	} else {
		node = peer->getdata;
		while (node->next) {
			node = node->next;
		}
		node->next = (struct BMGetdata*)malloc(sizeof(struct BMGetdata));
		node = node->next;
	}
	if (node == NULL) {
		bmLog(__FUNCTION__, "Faield to malloc!");
		return;
	}
	//Set value
	memset(node, 0, sizeof(struct BMGetdata));
	memcpy(node->inv, inv, BM_INV_SIZE);
	peer->getdataCount++;
}

int bmPeerSendGetdata(struct BMPeer* peer) {
	void* buffer;
	int bufferSize;
	uint8_t* p;
	struct BMGetdata* node;
	struct BMGetdata* nextNode;
	int byteSent;
	int temp;
	void* packet;

	//Parameter check
	if (peer->getdataCount == 0 || peer->getdata == NULL) {
		bmLog(__FUNCTION__, "No inv to send");
		return 1;
	}
	fprintf(stderr, "getdatacount=%u\n", peer->getdataCount);
	//Create buffer
	bufferSize = peer->getdataCount * BM_INV_SIZE + sizeof(uint64_t);
	buffer = malloc(bufferSize);
	if (buffer == NULL) {
		bmLog(__FUNCTION__, "malloc failed");
		return 0;
	}
	memset(buffer, 0, bufferSize);
	p = (uint8_t*)buffer;
	//Write count
	p += bmWriteVarint(peer->getdataCount, p);
	//Write inv vector
	node = peer->getdata;
	peer->getdata = NULL;
	while (node) {
		nextNode = node->next;
		memcpy(p, node->inv, BM_INV_SIZE);
		p += BM_INV_SIZE;
		free(node);
		node = nextNode;
	}
	//Send buffer
	bufferSize = p - (uint8_t*)buffer;
	packet = NULL;
	bufferSize = bmCreatePacket("getdata", buffer, bufferSize, &packet);
	free(buffer);
	buffer = NULL;
	if (bufferSize == 0) {
		bmLog(__FUNCTION__, "Create packet failed");
		return 0;
	}
	byteSent = 0;
	while (byteSent < bufferSize) {
		temp = send(peer->sock, packet + byteSent, bufferSize - byteSent, 0);
		if (temp == -1) {
			bmLog(__FUNCTION__, "Connection error!");
			bmLog(__FUNCTION__, strerror(errno));
			free(packet);
			return 0;
		}
		byteSent += temp;
	}
	free(packet);
	packet = NULL;
	bmLog(__FUNCTION__, "getdata send");
	return 1;
}

//PRIVATE
void connectHost(struct BMPeer* peer) {
	struct sockaddr_in sin;
	//Create socket
	peer->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (peer->sock == -1) {
		bmLog(__FUNCTION__, "Failed to create socket!");
		return;
	}
	//Connect to host
	memset(&sin, 0, sizeof(struct sockaddr));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(peer->port);
	inet_pton(AF_INET, peer->host, &sin.sin_addr.s_addr);
	if (connect(peer->sock, (struct sockaddr*)&sin, sizeof(struct sockaddr)) == -1) {
		bmLog(__FUNCTION__, "Failed to connect!");
	}
}

void firstHandshake(struct BMPeer* peer) {
	struct BMHeader header;
	void* payload;

	sendVersion(peer);
	payload = NULL;
	recvPacket(peer, &header, &payload);
	if (strcmp((const char*)header.command, "verack") != 0) {
		if (payload != NULL) {
			free(payload);
		}
		bmLog(__FUNCTION__, "Handshake error!");
		return;
	}
	payload = NULL;
	recvPacket(peer, &header, &payload);
	if (strcmp((const char*)header.command, "version") != 0) {
		if (payload != NULL) {
			free(payload);
		}
		bmLog(__FUNCTION__, "Handshake error!");
		return;
	}
	//TODO: Check info from payload
	//TODO: Get info from payload
	if (payload != NULL) {
		free(payload);
	}
	sendVerack(peer);
}

void sendVersion(struct BMPeer* peer) {
	void* payload;
	void* packet;
	unsigned int payloadLength;
	unsigned int packetLength;
	unsigned int temp;
	unsigned int byteSent;
	//Send version packet
	payload = NULL;
	payloadLength = bmCreateVersionPayload(peer->host, peer->port, &payload);
	if (payload == NULL) {
		bmLog(__FUNCTION__, "Failed to cerate version payload");
	}
	packet = NULL;
	packetLength = bmCreatePacket("version", payload, payloadLength, &packet);
	if (packet == NULL) {
		bmLog(__FUNCTION__, "Failed to create version packet");
	}
	free(payload);
	payload = NULL;
	byteSent = 0;
	while (byteSent < packetLength) {
		temp = send(peer->sock, ((const char*)packet) + byteSent, packetLength - byteSent, 0);
		if (temp == -1) {
			bmLog(__FUNCTION__, "Connection error!");
		}
		byteSent += temp;
	}
	free(packet);
	packet = NULL;
}

void sendVerack(struct BMPeer* peer) {
	void* packet;
	int packetLength;
	int temp;
	int byteSent;
	//Send verack packet
	packet = NULL;
	packetLength = bmCreatePacket("verack", NULL, 0, &packet);
	if (packet == NULL) {
		bmLog(__FUNCTION__, "Failed to create verack packet!");
		return;
	}
	byteSent = 0;
	while (byteSent < packetLength) {
		temp = send(peer->sock, ((const char*)packet) + byteSent, packetLength - byteSent, 0);
		if (temp == -1) {
			bmLog(__FUNCTION__, "Connection error!");
		}
		byteSent += temp;
	}
	free(packet);
	packet = NULL;
}

void bmPeerSendPong(struct BMPeer* peer) {
	void* packet;
	int packetLength;
	int temp;
	int byteSent;
	//Send verack packet
	packet = NULL;
	packetLength = bmCreatePacket("pong", NULL, 0, &packet);
	if (packet == NULL) {
		bmLog(__FUNCTION__, "Failed to create pong packet!");
		return;
	}
	byteSent = 0;
	while (byteSent < packetLength) {
		temp = send(peer->sock, ((const char*)packet) + byteSent, packetLength - byteSent, 0);
		if (temp == -1) {
			bmLog(__FUNCTION__, "Connection error!");
		}
		byteSent += temp;
	}
	free(packet);
	packet = NULL;
}

void recvPacket(struct BMPeer* peer, struct BMHeader* header, void** payload) {
	unsigned int byteRecv;
	unsigned int temp;
	unsigned int payloadLength;

	if (header == NULL || payload == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter!");
		return;
	}
	byteRecv = 0;
	while (byteRecv < sizeof(struct BMHeader)) {
		temp = recv(peer->sock, (char*)header + byteRecv, sizeof(struct BMHeader) - byteRecv, 0);
		if (temp == -1) {
			bmLog(__FUNCTION__, "Connection error!");
			return;
		}
		byteRecv += temp;
	}
	if (ntohl(header->magic) != BM_MAGIC) {
		bmLog(__FUNCTION__, "Invalid packet received!");
		return;
	}
	payloadLength = ntohl(header->payloadLength);
	if (payloadLength == 0) {
		if (!bmCheckChecksum(NULL, 0, header->checksum)) {
			bmLog(__FUNCTION__, "Damaged packet received!");
			return;
		}
	} else {
		*payload = NULL;
		*payload = malloc(payloadLength);
		if (*payload == NULL) {
			bmLog(__FUNCTION__, "Failed to malloc!");
			return;
		}
		byteRecv = 0;
		while (byteRecv < payloadLength) {
			temp = recv(peer->sock, (char*)*payload + byteRecv, payloadLength - byteRecv, 0);
			if (temp == -1) {
				free(*payload);
				*payload = NULL;
				bmLog(__FUNCTION__, "Connection error!");
				return;
			}
			byteRecv += temp;
		}
		if (!bmCheckChecksum(*payload, payloadLength, header->checksum)) {
			free(*payload);
			*payload = NULL;
			bmLog(__FUNCTION__, "Damaged packet received!");
			return;
		}
	}
}

void* listenThread(void* data) {
	struct BMPeer* peer;
	if (data == NULL) {
		bmLog(__FUNCTION__, "Parameter errro!");
		return 0;
	}
	peer = (struct BMPeer*)data;
	listenSocket(peer);
	return 0;
}

void listenSocket(struct BMPeer* peer) {
	struct BMHeader header;
	void* payload;
	while (1) {
		payload = NULL;
		memset(&header, 0, sizeof(struct BMHeader));
		recvPacket(peer, &header, &payload);
		processPacket(peer, &header, payload);
		if (payload != NULL) {
			free(payload);
		}
		sleep(1);
	}
}

void processPacket(struct BMPeer* peer, struct BMHeader* header, void* payload) {
	uint64_t count;
	uint8_t* p;
	int i;
	uint8_t inv[BM_INV_SIZE];
	struct BMNetAddress* addr;

	p = (uint8_t*)payload;
	if (strcmp((const char*)header->command, "inv") == 0) {
		p += bmReadVarint(payload, &count);
		bmLog(__FUNCTION__, "%lu inv received", count);
		for (i = 0; i < count; i++) {
			memset(inv, 0, BM_INV_SIZE);
			memcpy(inv, p, BM_INV_SIZE);
			p += BM_INV_SIZE;
			if (!bmInvInsertNode(BM_GLOBAL_INV, inv, peer)) {
				bmLog(__FUNCTION__, "Failed to insert inv");
			} 
		}
	} else if (strcmp((const char*)header->command, "ping") == 0) {
		bmLog(__FUNCTION__, "ping received");
		bmPeerSendPong(peer);
	} else if (strcmp((const char*)header->command, "addr") == 0) {
		bmLog(__FUNCTION__, "addr received");
		p += bmReadVarint(payload, &count);
		for (i = 0; i < count; i++) {
			addr = (struct BMNetAddress*)p;
			//TODO:Save the address to known host list
			p += sizeof(struct BMNetAddress);
		}
	} else if (strcmp((const char*)header->command, "getdata") == 0) {
		bmLog(__FUNCTION__, "getdata received");
		p += bmReadVarint(payload, &count);
		for (i = 0; i < count; i++) {
			//TODO:Search inventory vector if we have that object
			//TODO:Send object if we have that object
			p += BM_INV_SIZE;
		}
	} else if (strcmp((const char*)header->command, "object") == 0) {
		//TODO:Handle object
		bmLog(__FUNCTION__, "object recevied!");
		if (!bmObjectHandle(payload, ntohl(header->payloadLength))) {
			bmLog(__FUNCTION__, "failed to handle object!");
		}
	} else {
		bmLog(__FUNCTION__, "Unrecongized command received!");
	}
}
