#ifndef OBJECT_H
#define OBJECT_H

#include <stdint.h>

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
