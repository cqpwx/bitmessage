#ifndef INV_H
#define INV_H

#include <stdint.h>
#include <pthread.h>

#include "peer.h"
#include "protocol.h"

struct BMInvNode {
	uint8_t inv[BM_INV_SIZE];
	int isNew;
	struct BMPeer* peer;
	struct BMInvNode* next;
};

struct BMInv {
	int count;
	pthread_t watch;
	struct BMInvNode* data;
};


/*
* Description:
*	Create inv vector
* Return:
*	The inv created.
*/
struct BMInv* bmInvCreate();

/*
* Description:
*	Destory inv vector
* Input:
*	inv:Inv vector to destroy
*/
void bmInvDestory(struct BMInv* inv);

/*
* Description:
*	Insert inv into inv list
* Input:
*	list:List to insert
*	inv:Data to insert
*	peer:Where inv from
* Return:
*	1 if success or 0
*/
int bmInvInsertNode(struct BMInv* list, uint8_t* inv, struct BMPeer* peer);

/*
* Description:
*	Search from inv list if we have that inv
* Input:
*	list:Inv list
*	inv:Inv to search
* Return:
*	1 if found or 0.
*/
int bmInvSearchNode(struct BMInv* list, uint8_t* inv);

/*
* Description:
*	Delete inv from inv list
* Input:
*	list:Inv list
*	inv:Inv to delete
*/
void bmInvDeleteNode(struct BMInv* list, uint8_t* inv);

#endif
