seconn-avr
===========

seconn-avr is part of SeConn project. It's a protocol and set of libraries for secure communication. This repository contains AVR C++ library that implements the SeConn protocol. See also other repositories:

* [seconn](https://github.com/kacperzuk/seconn) - description of design and protocol, you should read it.
* [seconn-java](https://github.com/kacperzuk/seconn-java) - Java library that implements the SeConn protocol
* [seconn-android-example](https://github.com/kacperzuk/seconn-android-example) - Example Android project that uses seconn-java
* [seconn-arduino-example](https://github.com/kacperzuk/seconn-arduino-example) - Example Arduino sketch that uses seconn-avr

Adding to your project
----------------------

This repository contains git submodules. Run `git submodule update --init` in repository to download dependencies.

If you manage the build process yourself, add these to include path and build all \*.c and \*.cpp in these directories:

1. seconn/
2. ext-libs/micro-ecc/
3. ext-libs/avr-crypto-lib/gf256mul/
4. ext-libs/avr-crypto-lib/aes/
5. ext-libs/avr-crypto-lib/sha256/

If you're using Arduino:

1. Copy seconn directory to ~/Arduino/libraries
2. Copy ext-libs/micro-ecc directory to ~/Arduino/libraries
3. Copy ext-libs/avr-crypto-lib/gf256mul/ directory to ~/Arduino/libraries
4. Copy ext-libs/avr-crypto-lib/aes/ directory to ~/Arduino/libraries
5. Copy ext-libs/avr-crypto-lib/sha256/ directory to ~/Arduino/libraries

You can do it all with this oneliner (run in root directory of repository):

```bash
git submodule update --init && mkdir -p ~/Arduino/libraries && cp -r seconn ext-libs/micro-ecc ext-libs/avr-crypto-lib/{aes,sha256,gf256mul}/ ~/Arduino/libraries/
```

Usage
-----

seconn-avr is agnostic when it comes to the network layer, IO is abstracted away. So the first thing you have to do is to implement a few callbacks:

```c++
#include <seconn.h>

int c_seconn_write_data(void *src, size_t bytes) {
    /*
     * This callback is called when SeConn needs to write data to network.
     * For example we could pass this data to Arduino's SoftwareSerial used for
     * Bluetooth
     *
     * It should return number of bytes that were actually written.
     */

    return Bluetooth.write((const char*)src, bytes);
}

void c_seconn_data_received(void *src, size_t bytes) {
    /*
     * This callback is called when SeConn received data from the other side
     * of connection. This data was encrypted in the network and
     * authenticated using public key from SeConn.public_key.
     * In other words that's the data from EncryptedData frame of SeConn
     * protocol.
     *
     * IMPORTANT! It's up to you to make sure that the public_key is
     * trusted!  SeConn only makes sure that data was sent by owner of the
     * key, not that key is trusted!
     */

    Serial.println("New data received from SeConn:");
    Serial.write((const char*)src, bytes);
    Serial.println("");
}

void c_seconn_state_changed(State prev, State cur) {
    /*
     * This method is called when connection's state changes. Possible
     * values are:
     * - NEW - the starting state
     * - HELLO_REQUEST_SENT - we sent HelloRequest frame to the other end
     *   and are waiting for HelloResponse
     * - INVALID_HANDSHAKE - the other side didn't prove that they're
     *   owners of public key they sent us
     * - SYNC_ERROR - some violation of protocol happened and we can't recover
     * - AUTHENTICATED - the other side correctly proved they're owners of
     *   public key, we can now send and receive encrypted and
     *   authenticated messages.
     */

    Serial.print("SeConn state changed from ");
    Serial.print(previous_state);
    Serial.print(" to ");
    Serial.println(current_state);
}
```

These callback cover receiving decrypted data in your app and sending raw data from SeConn to network. To transfer raw data from network to SeConn and to transfer data you want encrypted from your app to SeConn you'll have to use SeConn object. You also need a way to generate random bytes. If you're using arduino, you can use micro-library from arduino-rng directory in this repository.

```c++
#include <seconn.h>

// function that will write size bytes to dest
int RNG(uint8_t *dest, unsigned size);

struct SeConn seConn;

// eeprom_offset says where in internal eeprom keys should be stored
int eeprom_offset = 0;
seconn_init(
    &seConn,
    c_seconn_write_data,
    c_seconn_data_received,
    c_seconn_state_changed,
    &RNG,
    eeprom_offset);

// you can get your public key immediately, for example to show it to user for
// verification
// do not confuse seconn_get_public_key() with seConn.public_key! see below.
uint8_t public_key[64];
seconn_get_public_key(&seConn, public_key);
Serial.print("My public key is: ");
printHex(public_key, 64);
Serial.println("");

// after the state is AUTHENTICATED
// passing data that should be encrypted and sent to other side:
const char *data[] = "Hello from the other side!";
seconn_write_data(&seConn, data, sizeof(data));

// you can get the public key of the other side
//
// IMPORTANT! It's up to you to make sure that the public_key is
// trusted!  SeConn only makes sure that data was sent by owner of the
// key, not that key is trusted!

Serial.print("Public key of the other side is: ");
Serial.println(seConn.public_key);

// passing data from network to SeConn
while(Bluetooth.available()) {
    char c = Bluetooth.read();
    seconn_new_data(&seconn, &c, 1);
}
```
