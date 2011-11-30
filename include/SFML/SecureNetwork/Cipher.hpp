#ifndef __H_CIPHER
#define __H_CIPHER

#include <openssl/rand.h>

namespace sf {

enum CipherType {
  CIPHER_RC4 = 0,
  CIPHER_AES = 1
};

  /**
   * Abstract class used as a base for all concrete stream ciphers
   */
class Cipher {

protected:
    int _keyLength;
    unsigned char * _key;
    CipherType _cipherType;

public:

    /**
     * Initializes a Cipher object.
     * If no key is given, a random one is generated automatically using a secure random generator.
     * @param keyLength the length of the key, in bytes
     * @param key (optionnal) a custom key you made
     */
    Cipher(int keyLength, unsigned char* key = 0) : _keyLength(keyLength), _key(key) {
        if(key == 0) {
            _key = new unsigned char[keyLength];
            RAND_bytes(_key, keyLength);
        }
    }
    
    virtual ~Cipher() {
        delete _key;
    }

    /**
     * Encrypts data of a certain length
     * @param Data the data to encrypt
     * @param length the initial length of the data. It is modified and contains the new length at the end of the method
     * @return pointer to the encrypted data
     */
    virtual char* encrypt(const char* Data, int& length) = 0;

    /**
     * Decrypts data of a certain length
     * @param Data the data to encrypt
     * @param length the size in bytes of the data
     * @return pointer to the decrypted data
     */
    virtual char* decrypt(const char* Data, int length) = 0;

    CipherType getCipherType() { return _cipherType; }

    /**
     * Returns the key size, in Bytes
     */
    int getKeyLength() { return _keyLength; }

    /**
     * Returns the symmetric key of the cipher
     */
    const unsigned char* getKey() { return _key; }

};

}

#endif
