#include "inv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>

#include "protocol.h"
#include "log.h"

/*
 * Descritption:
 *	Watch inv list if have new inv
 *	send getdata packet to get new object
 * Input:
 *	inv:Inv to watch
 */
void watch(struct BMInv* inv);

//EXTERN
extern struct BMPeerList* BM_GLOBAL_PEERS;

//THREAD
void* watchThread(void* data);

//PUBLIC
struct BMInv* bmInvCreate() {
	struct BMInv* result;

	result = (struct BMInv*)malloc(sizeof(struct BMInv));
	if (result == NULL) {
		bmLog(__FUNCTION__, "Failed to malloc\n");
		return NULL;
	}
	memset(result, 0, sizeof(struct BMInv));

	if (pthread_create(&result->watch, NULL, watchThread, (void*)result)) {
		bmLog(__FUNCTION__, "Failed to create inv watch thread!\n");
		free(result);
		return NULL;
	}

	return result;
}

void bmInvDestory(struct BMInv* inv) {
	struct BMInvNode* node;
	struct BMInvNode* next;

	//Parameter check
	if (inv == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter!\n");
		return;
	}
	//Destroy inv data
	node = inv->data;
	while (node) {
		next = node->next;
		free(node);
		node = next;
	}
	//Destory inv
	free(inv);
}

int bmInvInsertNode(struct BMInv* list, unsigned char* inv, struct BMPeer* peer) {
	struct BMInvNode* node;
	//Parameter check
	if (list == NULL || inv == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter input!\n");
		return 0;
	}
	//Search if we have that inv
	if (bmInvSearchNode(list, inv)) {
		bmLog(__FUNCTION__, "Already in the list,Ignored.");
		return 0;
	}
	//Insert
	if (list->data == NULL) {
		list->data = (struct BMInvNode*)malloc(sizeof(struct BMInvNode));
		node = list->data;
	} else {
		node = list->data;
		while (node->next) {
			node = node->next;
		}
		node->next = (struct BMInvNode*)malloc(sizeof(struct BMInvNode));
		node = node->next;
	}
	if (node == NULL) {
		bmLog(__FUNCTION__, "Failed to malloc\n");
		return 0;
	}
	memset(node, 0, sizeof(struct BMInvNode));
	memcpy(node->inv, inv, BM_INV_SIZE);
	node->isNew = 1;
	node->peer = peer;
	list->count++;
	return 1;
}

int bmInvSearchNode(struct BMInv* list, unsigned char* inv) {
	struct BMInvNode* node;
	//Parameter check
	if (list == NULL || inv == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter input!\n");
		return 0;
	}
	//Search
	node = list->data;
	while (node) {
		if (memcmp(node->inv, inv, BM_INV_SIZE) == 0) {
			return 1;
		}
		node = node->next;
	}
	return 0;
}

void bmInvDeleteNode(struct BMInv* list, unsigned char* inv) {
	struct BMInvNode* pre;
	struct BMInvNode* node;
	//Parameter check
	if (list == NULL || inv == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter input!\n");
		return;
	}
	//Search and delete
	pre = NULL;
	node = list->data;
	while (node) {
		if (memcmp(node->inv, inv, BM_INV_SIZE) == 0) {
			if (pre == NULL) {
				free(list->data);
				list->data = NULL;
			} else {
				pre->next = node->next;
				free(node);
			}
			return;
		}
		pre = node;
		node = node->next;
	}
}

//THREAD
#define TIME_TO_SLEEP 60
void* watchThread(void* data) {
	struct BMInv* inv = (struct BMInv*)data;
	if (data == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter!\n");
		return 0;
	}
	while (1) {
		watch(inv);
		sleep(TIME_TO_SLEEP);
	}
	return 0;
}

//PRIVATE
void watch(struct BMInv* inv) {
	struct BMInvNode* invNode;
	struct BMPeerNode* peerNode;
	int haveNew = 0;

	invNode = inv->data;
	while (invNode) {
		if (invNode->isNew) {
			bmPeerAddGetdata(invNode->peer, invNode->inv);
			invNode->isNew = 0;
			haveNew = 1;
		}
		invNode = invNode->next;
	}
	if (haveNew) {
		peerNode = BM_GLOBAL_PEERS->data;
		while (peerNode) {
			bmPeerSendGetdata(peerNode->peer);
			peerNode = peerNode->next;
		}
	}
}
