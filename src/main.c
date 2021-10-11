#include <stdio.h>

#include "peer.h"
#include "address.h"

struct BMInv* BM_GLOBAL_INV = NULL;
struct BMPeerList* BM_GLOBAL_PEERS = NULL;

int main(int argc, char* argv[]) {
//	struct BMPeer* peer;
    unsigned char address[64] = {0};

//	BM_GLOBAL_INV = bmInvCreate();
//	BM_GLOBAL_PEERS = bmPeersCreate();
//
//	peer = bmPeerCreate("192.168.3.10", 8444);
//	if (peer == NULL) {
//		fprintf(stderr, "Failed to create peer!\n");
//		return 0;
//	}
//	if (!bmPeersAdd(BM_GLOBAL_PEERS, peer)) {
//		fprintf(stderr, "Failed to add peer to list!\n");
//		return 0;
//	}

    bmAddressGenerateRandom(address);
    printf("BM-%s\n", address);
    return 0;
}
