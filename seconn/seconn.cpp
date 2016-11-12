#include "seconn.h"

#include <string.h>

#include "proto.h"
#include "crypto.h"

size_t written;
void write_bytes(struct seconn *conn, uint8_t *buffer, size_t bytes) {
    written = 0;
    while(written < bytes) {
        written += conn->writeData(buffer + written, bytes - written);
    }
}

void send_hello_request(struct seconn *conn) {
    uint8_t *key = conn->msg.message.hello_request.public_key;
    _seconn_crypto_get_public_key(key);
    _seconn_proto_create_message_header(conn->buffer, HelloRequest, 64);
    write_bytes(conn, conn->buffer, HEADER_LENGTH);
    write_bytes(conn, key, 64);
}

void send_hello_response(struct seconn *conn) {
    uint8_t *key = conn->msg.message.hello_request.public_key;
    _seconn_crypto_get_public_key(key);

    size_t l = _seconn_crypto_encrypt_then_mac(conn->buffer + HEADER_LENGTH, key, 64, conn->mac_key, conn->enc_key);
    _seconn_proto_create_message_header(conn->buffer, HelloResponse, l);
    write_bytes(conn, conn->buffer, HEADER_LENGTH);
    write_bytes(conn, conn->buffer + HEADER_LENGTH, l);
}

void change_state(struct seconn *conn, seconn_state new_state) {
    seconn_state prev_state = conn->state;
    conn->state = new_state;
    conn->onStateChange(prev_state, conn->state);
}

void seconn_init(struct seconn *conn,
        int (*writeData)(void *src, size_t bytes),
        void (*onDataReceived)(void *src, size_t bytes),
        void (*onStateChange)(seconn_state prev_state, seconn_state cur_state),
        int (*rng)(uint8_t *dest, unsigned size),
        int eeprom_offset) {

    _seconn_crypto_set_rng(rng);

    memset(conn, 0, sizeof(struct seconn));
    conn->state = NEW;
    conn->writeData = writeData;
    conn->onDataReceived = onDataReceived;
    conn->onStateChange = onStateChange;
    _seconn_crypto_init(eeprom_offset);
}

void seconn_new_data(struct seconn *conn, const void *data, size_t bytes) {
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
    int ret = _seconn_proto_parse_message(&(conn->msg), conn->buffer, conn->bytes_in_buffer, &bytes_consumed);
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
        _seconn_crypto_calculate_shared_secret(conn->public_key, (shared_secret_t*)conn->buffer);
        memcpy(conn->enc_key, conn->buffer, 16);
        memcpy(conn->mac_key, conn->buffer + 16, 16);
        if (conn->state == NEW) {
            send_hello_request(conn);
        }
        send_hello_response(conn);
    } else if (conn->msg.type == HelloResponse) {
        struct _seconn_proto_hello_response_payload_t *payload = &(conn->msg.message.hello_response);
        if(0 != _seconn_crypto_check_mac(payload->mac, payload->encrypted_public_key, sizeof(payload->encrypted_public_key), conn->mac_key)) {
            change_state(conn, INVALID_HANDSHAKE);
            return;
        }
        size_t l = _seconn_crypto_decrypt(conn->buffer, payload->encrypted_public_key, sizeof(payload->encrypted_public_key), conn->enc_key);
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
        struct _seconn_proto_encrypted_data_payload_t *payload = &(conn->msg.message.encrypted_data);
        if(0 != _seconn_crypto_check_mac(payload->mac, payload->payload, conn->msg.payload_length-16, conn->mac_key)) {
            change_state(conn, SYNC_ERROR);
            return;
        }
        size_t l = _seconn_crypto_decrypt(conn->buffer, payload->payload, conn->msg.payload_length-16, conn->enc_key);
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

void seconn_write_data(struct seconn *conn, const void *source, size_t bytes) {
    size_t l = _seconn_crypto_encrypt_then_mac(conn->buffer + HEADER_LENGTH, (void*)source, bytes, conn->mac_key, conn->enc_key);
    _seconn_proto_create_message_header(conn->buffer, EncryptedData, l);
    write_bytes(conn, conn->buffer, HEADER_LENGTH);
    write_bytes(conn, conn->buffer + HEADER_LENGTH, l);
}

void seconn_get_public_key(struct seconn *conn, uint8_t *public_key) {
    _seconn_crypto_get_public_key(public_key);
}
