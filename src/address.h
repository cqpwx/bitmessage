#ifndef ADDRESS_H
#define ADDRESS_H

#define BM_ADDRESS_VERSION 4

struct BMAddress {
    unsigned char address[64];
    unsigned char privateSignKey[32];
    unsigned char privateEncryptKey[32];
    unsigned char publicSignKey[128];
    unsigned char publicEncryptionKey[128];
    unsigned char ripe[32];
    unsigned int addressLength;
    unsigned int publicSignKeyLength;
    unsigned int publicEncryptionKeyLength;
    unsigned int ripeLength;
};

/*
 * Description:
 *  Generate a random bitmessage address
 * Return:
 *  Address struct
 */
struct BMAddress* bmAddressGenerateRandom();

#endif //ADDRESS_H
