#ifndef OBJECT_H
#define OBJECT_H

#include <stdint.h>

struct BMObject {
    uint8_t objectType;
    uint8_t streamNumber;
    uint8_t* payload;
    uint64_t embeddedTime;
    uint8_t tag[32];
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

#endif
