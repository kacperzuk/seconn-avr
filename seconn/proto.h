#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include <stddef.h>

#define PROTOCOL_VERSION 0x0001
#define LOW_BYTE(x)     ((uint8_t)((x)&0xFF))
#define HIGH_BYTE(x)    ((uint8_t)(((x)>>8)&0xFF))

#define MAX_PAYLOAD_LENGTH 0x0120
#define HEADER_LENGTH 5
#define MAX_DATA_FOR_ENCRYPTION MAX_PAYLOAD_LENGTH-16-1
#define MAX_MESSAGE_SIZE MAX_PAYLOAD_LENGTH+HEADER_LENGTH

enum MessageType {
    HelloRequest = 0x00,
    HelloResponse = 0x01,
    EncryptedData = 0x02,
    MAX_MESSAGE_TYPE
};

struct HelloRequestPayload {
    uint8_t public_key[64];
};

struct HelloResponsePayload {
    uint8_t mac[16];
    uint8_t encrypted_public_key[96];
};

struct EncryptedDataPayload {
    uint8_t mac[16];
    uint8_t payload[MAX_PAYLOAD_LENGTH-16];
};

union AbstractPayload {
    HelloRequestPayload hello_request;
    HelloResponsePayload hello_response;
    EncryptedDataPayload encrypted_data;
};

struct Message {
    uint16_t protocol_version;
    MessageType type;
    uint16_t payload_length;
    AbstractPayload message;
};

/*
 * destination - buffer for header
 * type - message type
 * len - length of source data in bytes
 *
 * returns: header size
 */
int CreateMessageHeader(void *destination, MessageType type, size_t len);

/*
 * dest - where parsed message should be written
 * source - bytes to parse
 * len - number of bytes to parse
 *
 * returns:
 * 0 on success
 * -1 if not enough to get length
 * -2 on invalid protocol version
 * -3 when payload length in message doesnt match whats expected for type
 * -4 when payload length is too large
 * -5 on invalid message type
 * +n when n more bytes are needed to parse
 *
 *
 * note: if lower layer protocol is streaming protocol, just pass first 5 bytes
 * of what you have and ParseMessage will return how much more bytes belong to
 * this single message
 */
int ParseMessage(Message *dest, const void* source, size_t len, size_t *bytes_consumed);

#endif // PROTO_H
