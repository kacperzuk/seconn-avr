#ifndef SECONN_H
#define SECONN_H

#include <stdint.h>
#include "crypto.h"
#include "proto.h"

enum State {
    NEW, // no data sent whatsoever
    HELLO_REQUEST_SENT,
    INVALID_HANDSHAKE, // couldn't connect
    SYNC_ERROR,
    AUTHENTICATED // make sure to check if you like the public key!
};

struct SeConn {
    // connection state
    State state;

    // public key of other side
    pubkey_t public_key;

    // callback that will be used to writeData to network
    int (*writeData)(void *src, size_t bytes);

    // callback that will be used to return authenticated data
    void (*onDataReceived)(void *src, size_t bytes);

    // callback that will be called on state change
    void (*onStateChange)(State prev_state, State cur_state);

    // used internally:
    Message msg;
    uint8_t enc_key[16];
    uint8_t mac_key[16];
    uint8_t buffer[MAX_MESSAGE_SIZE];
    size_t bytes_in_buffer;
};

void seconn_init(SeConn *conn,
        int (*writeData)(void *src, size_t bytes),
        void (*onDataReceived)(void *src, size_t bytes),
        void (*onStateChange)(State prev_state, State cur_state),
        int (*rng)(uint8_t *dest, unsigned size),
        int eeprom_offset);
void seconn_new_data(SeConn *conn, const void *data, size_t bytes);
void seconn_write_data(SeConn *conn, const void *source, size_t bytes);
void seconn_get_public_key(SeConn *conn, uint8_t *public_key);

#endif //SECONN_H
