#ifndef PEER_H
#define PEER_H

#include "inv.h"
#include "protocol.h"

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>

struct BMGetdata {
	uint8_t inv[32];
	struct BMGetdata* next;
};

struct BMPeer {
	char* host;
	unsigned short port;
	int sock;
	pthread_t thread;
	struct BMGetdata* getdata;
    int getdataCount;
};

struct BMPeerNode {
	struct BMPeer* peer;
	struct BMPeerNode* next;
};

struct BMPeerList {
	unsigned int count;
	struct BMPeerNode* data;
};

/*
 * Description:
 *	Create peers list
 * Return:
 *	BMPeers struct
 */
struct BMPeerList* bmPeersCreate();

/*
 * Description:
 *	Add a peer to peers list
 * Input:
 *	list:list to add
 *	peer:Peer to add
 * Return:
 *	1 if success or 0
 */
int bmPeersAdd(struct BMPeerList* list, struct BMPeer* peer);

/*
* Description:
*	Create peer with host and port
* Input:
*	host:Host IP to connect
*	port:Host port to connect
* Return:
*	BMPeer struct
*/
struct BMPeer* bmPeerCreate(const char* host, unsigned short port);

/*
 * Description:
 *	Add inv to getdata list
 * Input:
 *  peer:Peer to add to
 *  inv:inv to add
 */
void bmPeerAddGetdata(struct BMPeer* peer, uint8_t* inv);

/*
 * Description:
 *	Send getdata to peer
 * Input:
 *	peer:Peer to send
 * Return:
 *	1 if success or 0
 */
int bmPeerSendGetdata(struct BMPeer* peer);

#endif
