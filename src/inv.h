#ifndef INV_H
#define INV_H

#include <stdint.h>
#include <pthread.h>
#include <uthash.h>

#include "peer.h"
#include "protocol.h"
#include "object.h"

struct BMInvData {
    unsigned char inv[32];
    struct BMObject* data;
	struct BMPeer* peer;
    int need;
    UT_hash_handle hh;
};

struct BMInv {
	pthread_t watch;
	struct BMInvData* data;
};


/*
* Description:
*	Create inv hash table
* Return:
*	The inv created.
*/
struct BMInv* bmInvCreate();

/*
* Description:
*	Destory inv hash table
* Input:
*	inv:Inv hash table to destroy
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
int bmInvInsertNodeWithPeer(struct BMInv* list, uint8_t* inv, struct BMPeer* peer);

/*
* Description:
*	Insert inv into inv list
* Input:
*	list:List to insert
*	inv:Inv to insert
*	object:Inv data
* Return:
*	1 if success or 0
*/
int bmInvInsertNodeWithObject(struct BMInv* list, uint8_t* inv, struct BMObject* object);

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

/*
 * Description:
 *  Calculate inv from buffer
 * Input:
 *  data:Data to calculate
 *  length:Data length
 *  result:Calculate result
 */
void bmInvCalculate(unsigned char* data, unsigned int length, unsigned char* result);

/*
 * Description:
 *  Print inv
 * Input:
 *  inv: inv to print
 */
void bmInvPrint(unsigned char* inv);


#endif
