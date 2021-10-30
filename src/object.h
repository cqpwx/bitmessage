#ifndef OBJECT_H
#define OBJECT_H

#include <stdint.h>

#include "inv.h"

struct BMObject {
    uint8_t objectType;
    uint8_t streamNumber;
    uint8_t* payload;
    uint32_t payloadLength;
    uint64_t embeddedTime;
    uint8_t inv[BM_INV_SIZE];
};

/*
 * Description:
 *	Handle object packet
 * Input:
 *	payload:Object packet payload
 *	payloadLength:Object packet payload length
 * Return:
 *	1 if success or 0
 */
int bmObjectHandle(uint8_t* payload, uint64_t payloadLength);

/*
 * Description:
 *   Create pubkey object
 * Input:
 *   ripe:ripe hash
 *   ripeLength:ripe Length
 *   publicSigningKey:public sign key
 *   publicSigningKeyLength:public sign key length
 *   publicEncryptionKey:public encryption key
 *   publicEncryptionKeyLength:public encryption key length
 *   privateSigningKey:private signing key
 *   privateSigningKeyLength:private signing key length
 * Return:
 *   the object
 */
struct BMObject* bmObjectCreatePubkey(void* ripe, unsigned int ripeLength,
                                      void* publicSigningKey, unsigned int publicSigningKeyLength,
                                      void* publicEncryptionKey, unsigned int publicEncryptionKeyLength,
                                      void* privateSigningKey, unsigned int privateSigningKeyLength);
#endif
