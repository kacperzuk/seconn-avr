#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stdlib.h>

#define SECP256R1_CURVE_SIZE 32

typedef uint8_t pubkey_t[2*SECP256R1_CURVE_SIZE];
typedef uint8_t privkey_t[SECP256R1_CURVE_SIZE];
typedef uint8_t shared_secret_t[SECP256R1_CURVE_SIZE];
typedef uint8_t aes128_key_t[128/8];

void InitCrypto(int eeprom_offset);
void InitCrypto();
void SetRng(int (*rng)(uint8_t *dest, unsigned size));
void GetPubKey(uint8_t *pubkey);
void GetPrivKey(uint8_t *privkey);
void GetSharedSecret(const pubkey_t other_pubkey, shared_secret_t *secret);
void xor_block(void *vdest, void *vsrc);
void CalculateSignature(uint8_t *signature, void *message, size_t length, aes128_key_t mac_key);
size_t EncryptData(void *destination, void *src, size_t length, aes128_key_t enc_key);
size_t EncryptThenMac(void *destination, void *source, size_t length, aes128_key_t mac_key, aes128_key_t enc_key);
int CheckMac(void *mac, void *data, size_t data_length, aes128_key_t mac_key);
size_t Decrypt(void *destination, void *source, size_t length, aes128_key_t enc_key);

#endif // CRYPTO_H
