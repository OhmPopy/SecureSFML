#ifndef __H_AESCIPHER
#define __H_AESCIPHER

#include "Cipher.hpp"
#include <iostream>

namespace ssf {

class AESCipher : public Cipher {

public:

    /**
     * Initializes an AESCipher object.
     * If no key is given, a random one is generated automatically using a secure random generator.
     * @param keyLength the length of the key, in bytes (16, 24 or 32 only)
     * @param key (optionnal) a custom key you made
     */
    AESCipher(int keyLength, unsigned char* key = 0, unsigned char* iv = 0) : Cipher(keyLength, key, iv) {
      if(keyLength != 16 && keyLength != 24 && keyLength != 32)
        std::cerr << "Error : AES key length can be only 16/24/32 bytes" << std::endl;
      
      _cipherType = CIPHER_AES;
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

private:

    int getMissingBytes(int length);

};

} // namespace ssf

#endif
