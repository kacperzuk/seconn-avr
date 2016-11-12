#ifndef SECONN_PROTO_H
#define SECONN_PROTO_H

#include <stdint.h>
#include <stddef.h>

#define PROTOCOL_VERSION 0x0001
#define LOW_BYTE(x)     ((uint8_t)((x)&0xFF))
#define HIGH_BYTE(x)    ((uint8_t)(((x)>>8)&0xFF))

#define MAX_PAYLOAD_LENGTH 0x0120
#define HEADER_LENGTH 5
#define MAX_DATA_FOR_ENCRYPTION MAX_PAYLOAD_LENGTH-16-1
#define MAX_MESSAGE_SIZE MAX_PAYLOAD_LENGTH+HEADER_LENGTH

/*
 * map frame name to the hex value that has to be embedded in frame
 */
enum _seconn_proto_message_type {
    HelloRequest = 0x00,
    HelloResponse = 0x01,
    EncryptedData = 0x02,
    MAX_MESSAGE_TYPE
};

struct _seconn_proto_hello_request_payload_t {
    uint8_t public_key[64];
};

struct _seconn_proto_hello_response_payload_t {
    uint8_t mac[16];
    uint8_t encrypted_public_key[96];
};

struct _seconn_proto_encrypted_data_payload_t {
    uint8_t mac[16];
    uint8_t payload[MAX_PAYLOAD_LENGTH-16];
};

union _seconn_proto_abstract_payload_t {
    _seconn_proto_hello_request_payload_t hello_request;
    _seconn_proto_hello_response_payload_t hello_response;
    _seconn_proto_encrypted_data_payload_t encrypted_data;
};

struct _seconn_proto_message_t {
    uint16_t protocol_version;
    _seconn_proto_message_type type;
    uint16_t payload_length;
    _seconn_proto_abstract_payload_t message;
};

/*
 * destination - buffer for header
 * type - message type
 * len - length of source data in bytes
 *
 * returns: header size
 */
int _seconn_proto_create_message_header(void *destination, _seconn_proto_message_type type, size_t len);

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
 * of what you have and _seconn_proto_parse_message will return how much more bytes belong to
 * this single message
 */
int _seconn_proto_parse_message(_seconn_proto_message_t *dest, const void* source, size_t len, size_t *bytes_consumed);

#endif // SECONN_PROTO_H
