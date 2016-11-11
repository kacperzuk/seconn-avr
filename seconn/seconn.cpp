#include "seconn.h"

#include <string.h>

#include "proto.h"
#include "crypto.h"

size_t written;
void write_bytes(SeConn *conn, uint8_t *buffer, size_t bytes) {
    written = 0;
    while(written < bytes) {
        written += conn->writeData(buffer + written, bytes - written);
    }
}

void send_hello_request(SeConn *conn) {
    uint8_t *key = conn->msg.message.hello_request.public_key;
    GetPubKey(key);
    CreateMessageHeader(conn->buffer, HelloRequest, 64);
    write_bytes(conn, conn->buffer, HEADER_LENGTH);
    write_bytes(conn, key, 64);
}

void send_hello_response(SeConn *conn) {
    uint8_t *key = conn->msg.message.hello_request.public_key;
    GetPubKey(key);

    size_t l = EncryptThenMac(conn->buffer + HEADER_LENGTH, key, 64, conn->mac_key, conn->enc_key);
    CreateMessageHeader(conn->buffer, HelloResponse, l);
    write_bytes(conn, conn->buffer, HEADER_LENGTH);
    write_bytes(conn, conn->buffer + HEADER_LENGTH, l);
}

void change_state(SeConn *conn, State new_state) {
    State prev_state = conn->state;
    conn->state = new_state;
    conn->onStateChange(prev_state, conn->state);
}

void seconn_init(SeConn *conn,
        int (*writeData)(void *src, size_t bytes),
        void (*onDataReceived)(void *src, size_t bytes),
        void (*onStateChange)(State prev_state, State cur_state),
        int eeprom_offset) {

    memset(conn, 0, sizeof(SeConn));
    conn->state = NEW;
    conn->writeData = writeData;
    conn->onDataReceived = onDataReceived;
    conn->onStateChange = onStateChange;
    InitCrypto(eeprom_offset);
}

void seconn_new_data(SeConn *conn, const void *data, size_t bytes) {
    if(conn->state == SYNC_ERROR || conn->state == INVALID_HANDSHAKE) {
        return;
    }

    const uint8_t *src = (const uint8_t*)data;
    const uint8_t *remainder;
    size_t remainder_length = 0;

    size_t free_in_buffer = MAX_MESSAGE_SIZE - conn->bytes_in_buffer;
    if (bytes > free_in_buffer) {
        remainder_length = bytes - free_in_buffer;
        remainder = src + (MAX_MESSAGE_SIZE - conn->bytes_in_buffer);
        bytes = free_in_buffer;
    }

    memcpy(conn->buffer + conn->bytes_in_buffer, data, bytes);
    conn->bytes_in_buffer += bytes;

    size_t bytes_consumed = 0;
    int ret = ParseMessage(&(conn->msg), conn->buffer, conn->bytes_in_buffer, &bytes_consumed);
    if (ret == -1 || ret > 0) {
        // we need more data
        if (conn->bytes_in_buffer == MAX_MESSAGE_SIZE) {
            // but we have no more space!
            change_state(conn, SYNC_ERROR);
            conn->bytes_in_buffer = 0;
        }
        return;
    } else if (ret < 0) {
        // -2, invalid protocol version :(
        // -3, length doesnt match the message type
        // -4, whoa, too big payload length, we cant handle that
        // other: oops, we didn't handle something here
        change_state(conn, SYNC_ERROR);
        conn->bytes_in_buffer = 0;
        return;
    }

    // ret == 0, success

    memcpy(conn->buffer,
           conn->buffer + bytes_consumed,
           conn->bytes_in_buffer - bytes_consumed);
    conn->bytes_in_buffer = conn->bytes_in_buffer - bytes_consumed;

    if (conn->msg.type == HelloRequest) {
        memcpy(conn->public_key, conn->msg.message.hello_request.public_key, sizeof(conn->public_key));
        GetSharedSecret(conn->public_key, (shared_secret_t*)conn->buffer);
        memcpy(conn->enc_key, conn->buffer, 16);
        memcpy(conn->mac_key, conn->buffer + 16, 16);
        if (conn->state == NEW) {
            send_hello_request(conn);
        }
        send_hello_response(conn);
    } else if (conn->msg.type == HelloResponse) {
        struct HelloResponsePayload *payload = &(conn->msg.message.hello_response);
        if(0 != CheckMac(payload->mac, payload->encrypted_public_key, sizeof(payload->encrypted_public_key), conn->mac_key)) {
            change_state(conn, INVALID_HANDSHAKE);
            return;
        }
        size_t l = Decrypt(conn->buffer, payload->encrypted_public_key, sizeof(payload->encrypted_public_key), conn->enc_key);
        if (l != 64) {
            change_state(conn, INVALID_HANDSHAKE);
            return;
        }

        if (0 != strncmp((const char*)conn->public_key, (const char*)conn->buffer, 64)) {
            change_state(conn, INVALID_HANDSHAKE);
            return;
        }

        change_state(conn, AUTHENTICATED);
    } else if (conn->msg.type == EncryptedData) {
        struct EncryptedDataPayload *payload = &(conn->msg.message.encrypted_data);
        if(0 != CheckMac(payload->mac, payload->payload, conn->msg.payload_length-16, conn->mac_key)) {
            change_state(conn, SYNC_ERROR);
            return;
        }
        size_t l = Decrypt(conn->buffer, payload->payload, conn->msg.payload_length-16, conn->enc_key);
        if (l > MAX_MESSAGE_SIZE) {
            // FIXME that's bad, our memory is currupted already
            change_state(conn, SYNC_ERROR);
            return;
        }
        conn->onDataReceived(conn->buffer, l);
    } else {
        change_state(conn, SYNC_ERROR);
    }


    if (remainder_length > 0) {
        seconn_new_data(conn, remainder, remainder_length);
    }
}

void seconn_write_data(SeConn *conn, const void *source, size_t bytes) {
    size_t l = EncryptThenMac(conn->buffer + HEADER_LENGTH, (void*)source, bytes, conn->mac_key, conn->enc_key);
    CreateMessageHeader(conn->buffer, EncryptedData, l);
    write_bytes(conn, conn->buffer, HEADER_LENGTH);
    write_bytes(conn, conn->buffer + HEADER_LENGTH, l);
}
