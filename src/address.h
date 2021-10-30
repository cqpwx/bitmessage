#ifndef ADDRESS_H
#define ADDRESS_H

#define BM_ADDRESS_VERSION 4

/*
 * Description:
 *  Generate a random bitmessage address
 * Input:
 *  buffer:buffer to store address
 * Return:
 *  Address length
 */
int bmAddressGenerateRandom(void* buffer);

#endif //ADDRESS_H
