#include "inv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>

#include <openssl/evp.h>

#include "log.h"
#include "utils.h"

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
    struct BMInvData* data;
	//Parameter check
	if (inv == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter!\n");
		return;
	}
	//Destroy inv data
    for (data = inv->data; data != NULL; data = data->hh.next) {
        if (data->data) {
            if (data->data->payload) {
                free(data->data->payload);
            }
            free(data->data);
        }
        HASH_DEL(inv->data, data);
        free(data);
    }
	//Destory inv
	free(inv);
}

int bmInvInsertNodeWithPeer(struct BMInv* list, unsigned char* inv, struct BMPeer* peer) {
    struct BMInvData* data;
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
    data = (struct BMInvData*)malloc(sizeof(struct BMInvData));
    if (data == NULL) {
        bmLog(__FUNCTION__, "Failed to malloc!");
        return 0;
    }
    memset(data, 0, sizeof(struct BMInvData));
    data->peer = peer;
    data->need = 1;
    memcpy(data->inv, inv, BM_INV_SIZE);
    HASH_ADD(hh, list->data, inv, BM_INV_SIZE, data);
    return 1;
}

int bmInvInsertNodeWithObject(struct BMInv* list, struct BMObject* object) {
    struct BMInvData* data;
    //Parameter check
    if (list == NULL || object == NULL) {
        bmLog(__FUNCTION__, "Invalid parameter input!\n");
        return 0;
    }
    //Search if we have that inv
    if (bmInvSearchNode(list, object->inv)) {
        bmLog(__FUNCTION__, "Already in the list,Ignored.");
        return 0;
    }
    //Insert
    data = (struct BMInvData*)malloc(sizeof(struct BMInvData));
    if (data == NULL) {
        bmLog(__FUNCTION__, "Failed to malloc!");
        return 0;
    }
    memset(data, 0, sizeof(struct BMInvData));
    data->data = object;
    data->need = 0;
    memcpy(data->inv, object->inv, BM_INV_SIZE);
    HASH_ADD(hh, list->data, inv, BM_INV_SIZE, data);
    return 1;
}

int bmInvSearchNode(struct BMInv* list, unsigned char* inv) {
	struct BMInvData* node;
	//Parameter check
	if (list == NULL || inv == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter input!");
		return 0;
	}
	//Search
    HASH_FIND(hh, list->data, inv, BM_INV_SIZE, node);
	if (node != NULL) {
        return 1;
    }
	return 0;
}

void bmInvDeleteNode(struct BMInv* list, unsigned char* inv) {
	struct BMInvData* node;
	//Parameter check
	if (list == NULL || inv == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter input!");
		return;
	}
	//Search and delete
	HASH_FIND(hh, list->data, inv, BM_INV_SIZE, node);
    if (node != NULL) {
        HASH_DEL(list->data, node);
    }
}

void bmInvCalculate(unsigned char* data, unsigned int length, unsigned char* result) {
    unsigned char output[512] = { 0 };
    //Parameter Check
    if (data == NULL || result == NULL) {
        bmLog(__FUNCTION__, "Invalid parameter");
        return;
    }
    //Calcuate double hash
    bmUtilsCalculateDoubleHash(data, length, output);
    //Copy result
    memcpy(result, output, BM_INV_SIZE);
}

void bmInvPrint(unsigned char* inv) {
    int i;

    for (i = 0; i < BM_INV_SIZE; i++) {
        printf("%02x", inv[i]);
    }
    putchar('\n');
}

//THREAD
#define TIME_TO_SLEEP 20
void* watchThread(void* data) {
	struct BMInv* inv = (struct BMInv*)data;
	if (data == NULL) {
		bmLog(__FUNCTION__, "Invalid parameter");
		return 0;
	}
    //FIXME:How to quit this loop?
	while (1) {
		watch(inv);
		sleep(TIME_TO_SLEEP);
	}
	return 0;
}

//PRIVATE
void watch(struct BMInv* inv) {
	struct BMPeerNode* peerNode;
    struct BMInvData* data;

	for (data = inv->data; data != NULL; data = data->hh.next) {
        if (data->need) {
            bmPeerAddGetdata(data->peer, data->inv);
            data->need = 0;
        }
    }
    if (BM_GLOBAL_PEERS) {
        peerNode = BM_GLOBAL_PEERS->data;
    } else {
        peerNode = NULL;
    }
    while (peerNode) {
        bmPeerSendGetdata(peerNode->peer);
        peerNode = peerNode->next;
    }
}