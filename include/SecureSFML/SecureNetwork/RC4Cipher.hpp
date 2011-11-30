#ifndef __H_RC4CIPHER
#define __H_RC4CIPHER

#include "Cipher.hpp"

namespace ssf {

class RC4Cipher : public Cipher {

public:

    /**
     * Initializes a RC4 Cipher
     * If no key is given, a random one is generated automatically.
     * Default key length is 128 bits.
     * @param keyLength the length of the key, in bytes (16 Bytes minimum recommended for safety)
     * @param key (optionnal) a custom key you made
     */
    RC4Cipher(int keyLength = 16, unsigned char* key = 0) : Cipher(keyLength, key) {
      _cipherType = CIPHER_RC4;
    }

    /**
     * Encrypts data of a certain length
     * @param Data the data to encrypt
     * @param length the initial length of the data. It is modified and contains the new length at the end of the method
     * @return pointer to the encrypted data
     */
    virtual char* encrypt(const char* Data, int& length);

    /**
     * Decrypts data of a certain length
     * @param Data the data to encrypt
     * @param length the size in bytes of the data
     * @return pointer to the decrypted data
     */
    virtual char* decrypt(const char* Data, int length);

};

} // namespace ssf

#endif
