#ifndef SECONN_CRYPTO_H
#define SECONN_CRYPTO_H

#include <stdint.h>
#include <stdlib.h>

#define SECP256R1_CURVE_SIZE 32

typedef uint8_t pubkey_t[2*SECP256R1_CURVE_SIZE];
typedef uint8_t privkey_t[SECP256R1_CURVE_SIZE];
typedef uint8_t shared_secret_t[SECP256R1_CURVE_SIZE];
typedef uint8_t aes128_key_t[128/8];

/*
 * must be called first: set function that generates random data
 */
void _seconn_crypto_set_rng(int (*rng)(uint8_t *dest, unsigned size));

/*
 * Initialize crypto subsystem: load keys from eeprom or generate them.
 */
void _seconn_crypto_init(int eeprom_offset);
void _seconn_crypto_init();

/*
 * helpers to retrieve keys
 */
void _seconn_crypto_get_public_key(uint8_t *pubkey);
void _seconn_crypto_get_private_key(uint8_t *privkey);

/*
 * calculate shared secret between our privkey and provided pubkey
 */
void _seconn_crypto_calculate_shared_secret(const pubkey_t other_pubkey, shared_secret_t *secret);

/*
 * calculate signature (CBC-MAC, no padding) for message using mac_key
 */
void _seconn_crypto_calculate_signature(uint8_t *signature, void *message, size_t length, aes128_key_t mac_key);

/*
 * encrypt data (CBC, PKCS7 padding, block of random data prepended)
 */
size_t _seconn_crypto_encrypt(void *destination, void *src, size_t length, aes128_key_t enc_key);

/*
 * encrypt data and add MAC
 */
size_t _seconn_crypto_encrypt_then_mac(void *destination, void *source, size_t length, aes128_key_t mac_key, aes128_key_t enc_key);

/*
 * check MAC of data
 */
int _seconn_crypto_check_mac(void *mac, void *data, size_t data_length, aes128_key_t mac_key);

/*
 * decrypt data (doesnt check mac!!)
 */
size_t _seconn_crypto_decrypt(void *destination, void *source, size_t length, aes128_key_t enc_key);

// internal
void _seconn_crypto_xor_block(void *vdest, void *vsrc);
#endif // SECONN_CRYPTO_H
