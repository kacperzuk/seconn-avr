#ifndef SECONN_H
#define SECONN_H

#include <stdint.h>
#include "crypto.h"
#include "proto.h"

enum seconn_state {
    NEW, // no data sent whatsoever
    HELLO_REQUEST_SENT,
    INVALID_HANDSHAKE, // couldn't connect
    SYNC_ERROR,
    AUTHENTICATED // make sure to check if you like the public key!
};

struct seconn {
    // connection state
    seconn_state state;

    // public key of other side
    // dont confuse with seconn_get_public_key which retrieves our public key
    pubkey_t public_key;

    // callback that will be used to writeData to network
    int (*writeData)(void *src, size_t bytes);

    // callback that will be used to return authenticated data
    void (*onDataReceived)(void *src, size_t bytes);

    // callback that will be called on state change
    void (*onStateChange)(seconn_state prev_state, seconn_state cur_state);

    // used internally:
    _seconn_proto_message_t msg;
    uint8_t enc_key[16];
    uint8_t mac_key[16];
    uint8_t buffer[MAX_MESSAGE_SIZE];
    size_t bytes_in_buffer;
};

/*
 * initialize the seconn object.
 * writeData will be called when data must be sent to network
 * onDataReceived will be called when data has been received, authenticated and decrypted successfully
 * onStateChange will be called when connection state has changed
 * rng is a function that is used to generate random bytes
 * eeprom_offset defines where in eeprom keys should be stored
 */
void seconn_init(struct seconn *conn,
        int (*writeData)(void *src, size_t bytes),
        void (*onDataReceived)(void *src, size_t bytes),
        void (*onStateChange)(seconn_state prev_state, seconn_state cur_state),
        int (*rng)(uint8_t *dest, unsigned size),
        int eeprom_offset);

/*
 * seconn_new_data should be called each time there's new data in network that should be passed to seconn
 */
void seconn_new_data(struct seconn *conn, const void *data, size_t bytes);

/*
 * seconn_write_data should be called when app wants to encrypt, sign and send data to the other side of connection
 */
void seconn_write_data(struct seconn *conn, const void *source, size_t bytes);

/*
 * seconn_get_public_key will retrieve our public key.
 *
 * dont confuse with seconn.public_key, which holds public key of other side
 */
void seconn_get_public_key(struct seconn *conn, uint8_t *public_key);

#endif //SECONN_H
