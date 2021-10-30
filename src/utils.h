#ifndef UTILS_H
#define UTILS_H

/*
 * Description:
 *  Calculate hash
 * input:
 *  data:data to calculate
 *  length:data length
 * output:
 *  result:calculated hash data
 * return:
 *  hash length
 */
int bmUtilsCalculateHash(void* data, unsigned int length, void* result);

/*
 * Description:
 *  Calculate double hash
 * input:
 *  data:data to calculate
 *  length:data length
 * output:
 *  result:calculated hash data
 * return:
 *  hash length
 */
int bmUtilsCalculateDoubleHash(void* data, unsigned int length, void* result);

/*
 * Description:
 *  Calculate ripe hash
 * input:
 *  data:data to calculate
 *  length:data length
 * output:
 *  result:calculated hash data
 * return:
 *  hash length
 */
int bmUtilsCalculateRipeHash(void* data, unsigned int length, void* result);

/*
 * Description:
 *   Does an EC point multiplication; turns a private key into a public key.
 * Input:
 *  secret:private key
 *  result:public key
 * Return:
 *  pubkey size
 */
int bmUtilsPointMulti(unsigned char* secret, unsigned char* result);

/*
 * Description:
 *   Sign buffer using private sign key
 * Input:
 *   buffer:buffer to sign
 *   bufferLength:buffer length
 *   privateSignKey:private sign key
 *   privateSignKeyLength:private sign key length
 * Output:
 *   result:Buffer to store sign result
 * Return:
 *   result length
 */
int bmUtilsSigning(void* buffer, unsigned int bufferLength,
                   void* privateSignKey, unsigned int privateSignKeyLength,
                   void* result);
/*
 * Description:
 *   Encrypt buffer using public encryption key
 * Input:
 *   buffer: buffer to encrypt
 *   bufferLength:buffer length
 *   publicEncryptionKey:public encryption key
 *   publicEncryptionKeyLength:key length
 * Output:
 *   result:Buffer to store encrypt result
 * Return:
 *   result length
 */
int bmUtilsEncrypt(void* buffer, unsigned int bufferLength,
                   void* publicEncryptionKey, unsigned int publicEncryptionKeyLength,
                   void* result);

/*
 * Description:
 *   Calculate Proof of Work
 * Input:
 *   payload:Payload to calculate
 *   payloadLength:payload length
 *   ttl:ttl
 * Return:
 *   Nonce
 */
unsigned long long bmUtilsPOW(void* payload, unsigned int payloadLength, unsigned int ttl);

/*
 * Description:
 *   Calculate target value from TTL
 * Input:
 *   length:payload length
 *   ttl:ttl
 * Return:
 *   target value
 */
unsigned long long bmUtilsCalculateTarget(unsigned int length, unsigned int ttl);
#endif
