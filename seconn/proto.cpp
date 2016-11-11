#include "proto.h"

#include <string.h>

int CreateMessageHeader(void *destination, MessageType type, size_t len) {
    uint8_t *dest = (uint8_t*)destination;

    dest[0] = HIGH_BYTE(PROTOCOL_VERSION);
    dest[1] = LOW_BYTE(PROTOCOL_VERSION);

    dest[2] = type;

    dest[3] = HIGH_BYTE(len);
    dest[4] = LOW_BYTE(len);

    return len+5;
}

int ParseMessage(Message *dst, const void* source, size_t len, size_t *bytes_consumed) {
    uint8_t *src = (uint8_t*)source;
    uint8_t *payload = src+5;

    if (len < 5) {
        return -1;
    }

    if (src[0] != HIGH_BYTE(PROTOCOL_VERSION) || src[1] != LOW_BYTE(PROTOCOL_VERSION)) {
        return -2;
    }

    if (src[2] >= MAX_MESSAGE_TYPE) {
        return -5;
    }

    dst->protocol_version = PROTOCOL_VERSION;
    dst->type = (MessageType)src[2];
    dst->payload_length = (src[3] << 8) | src[4];

    if (len < 5 + dst->payload_length) {
        return 5 + dst->payload_length - len;
    }

    if (dst->payload_length > MAX_PAYLOAD_LENGTH) {
        return -4;
    }

    if (dst->type == HelloRequest) {
        if(dst->payload_length != 64) {
            return -3;
        }
        memcpy(dst->message.hello_request.public_key, payload, 64);
    } else if (dst->type == HelloResponse) {
        if(dst->payload_length != 16+96) {
            return -3;
        }
        memcpy(dst->message.hello_response.mac, payload, 16);
        memcpy(dst->message.hello_response.encrypted_public_key, payload+16, 96);
    } else if (dst->type == EncryptedData) {
        if(dst->payload_length < 32) {
            return -3;
        }
        memcpy(dst->message.encrypted_data.mac, payload, 16);
        memcpy(dst->message.encrypted_data.payload, payload+16, dst->payload_length - 16);
    }

    *bytes_consumed = dst->payload_length + 5;
    return 0;
}
