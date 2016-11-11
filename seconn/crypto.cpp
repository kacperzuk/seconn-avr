#include "crypto.h"

#include <string.h>
#include <EEPROM.h>

#define uECC_PLATFORM 7
#define uECC_SUPPORTS_secp160r1 0
#define uECC_SUPPORTS_secp192r1 0
#define uECC_SUPPORTS_secp224r1 0
#define uECC_SUPPORTS_secp256r1 1
#define uECC_SUPPORTS_secp256k1 0
#define uECC_SUPPORT_COMPRESSED_POINT 0

#include <types.h>
#include <uECC.h>
#include <uECC_vli.h>

extern "C" {
#include <sha256.h>
#include <aes.h>
}

#include <rng.h>

struct {
    uint8_t version;
    pubkey_t public_key;
    privkey_t private_key;
} device_keypair;

const struct uECC_Curve_t *curve;

void InitCrypto() {
    InitCrypto(0);
}

void InitCrypto(int eeprom_offset) {
    uECC_set_rng(&RNG);

    curve = uECC_secp256r1();

    EEPROM.get(eeprom_offset, device_keypair);
    if(device_keypair.version != 2) {
        uECC_make_key(device_keypair.public_key, device_keypair.private_key, curve);
        device_keypair.version = 2;
        EEPROM.put(eeprom_offset, device_keypair);
    }
}

void GetPubKey(uint8_t *pubkey) {
    memcpy(pubkey, &device_keypair.public_key, sizeof(pubkey_t));
}

void GetPrivKey(uint8_t *privkey) {
    memcpy(privkey, &device_keypair.private_key, sizeof(privkey_t));
}

void GetSharedSecret(const pubkey_t other_pubkey, shared_secret_t *secret) {
    shared_secret_t tmp;
    uECC_shared_secret(other_pubkey, device_keypair.private_key, tmp, curve);
    sha256(secret, tmp, SECP256R1_CURVE_SIZE*8);
}

void xor_block(void *vdest, void *vsrc) {
    uint8_t *dest = (uint8_t*)vdest;
    uint8_t *src = (uint8_t*)vsrc;
    for(int i = 0; i < 16; i++)
        dest[i] ^= src[i];
}

// signature has 16 bytes
aes128_ctx_t ctx;
void CalculateSignature(uint8_t *signature, void *message, size_t length, aes128_key_t mac_key) {
    memset(&ctx, 0, sizeof(aes128_ctx_t));
    aes128_init(mac_key, &ctx);

    uint8_t *block = signature;

    memset(block, 0, 16); // IV of zeros

    size_t i = 0;
    for(; i+16 <= length; i += 16) {
        xor_block(block, ((uint8_t*)message)+i);
        aes128_enc(block, &ctx);
    }
}

/* destination must be a buffer of at least max payload size! 1056B, 0x0420. */
size_t EncryptData(void *destination, void *source, size_t length, aes128_key_t enc_key) {
    uint8_t *dest = (uint8_t*)destination;
    uint8_t *src = (uint8_t*)source;

    RNG(dest, 16); // random first block
    memset(&ctx, 0, sizeof(aes128_ctx_t));

    aes128_init(enc_key, &ctx);

    aes128_enc(dest, &ctx);

    size_t i = 0;
    for(; i+16 <= length; i += 16) {
        memcpy(dest+16+i, src+i, 16);
        xor_block(dest+16+i, dest+i);
        aes128_enc(dest+16+i, &ctx);
    }

    size_t pad_length = 16 - (length % 16);
    memset(dest+16+i, pad_length, 16);
    memcpy(dest+16+i, src+i, length - i);
    xor_block(dest+16+i, dest+i);
    aes128_enc(dest+16+i, &ctx);

    return i+32;
}

size_t EncryptThenMac(void *destination, void *source, size_t length, aes128_key_t mac_key, aes128_key_t enc_key) {
    uint8_t *dest = (uint8_t*)destination;
    uint8_t *src = (uint8_t*)source;
    size_t l = EncryptData(dest+16, source, length, enc_key);
    CalculateSignature(dest, dest+16, l, mac_key);
    return l+16;
}

uint8_t signature[16];
int CheckMac(void *mac, void *source, size_t length, aes128_key_t mac_key) {
    CalculateSignature(signature, source, length, mac_key);
    // FIXME its not constant time here
    return strncmp((const char*)signature, (const char*)mac, 16);
}

size_t Decrypt(void *destination, void *source, size_t length, aes128_key_t enc_key) {
    uint8_t *src = ((uint8_t*)source);
    uint8_t *dest = (uint8_t*)destination;

    memset(&ctx, 0, sizeof(aes128_ctx_t));
    aes128_init(enc_key, &ctx);

    size_t i = 0;
    for(; i+16 < length; i += 16) {
        memcpy(dest+i, src+i+16, 16);
        aes128_dec(dest+i, &ctx);
        xor_block(dest+i, src+i);
    }

    size_t pad_length = dest[i-1];
    for(size_t j = 2; j <= pad_length; j++) {
        if (dest[i-j] != pad_length) {
            return 0;
        }
    }

    return i-pad_length;
}
