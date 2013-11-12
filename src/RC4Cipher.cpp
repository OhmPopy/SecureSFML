#include "RC4Cipher.hpp"
#include <openssl/rc4.h>
#include <openssl/sha.h>

namespace ssf {

char* RC4Cipher::encrypt(const char* Data, std::size_t& length) {

    RC4_KEY rc4Key;
    RC4_set_key(&rc4Key, _keyLength, _key);

    unsigned char * crypted = new unsigned char[length];
    RC4(&rc4Key, length, reinterpret_cast<const unsigned char*>(Data), crypted);
    
    // Calculate a new key which is SHA256(concat(key, iv))
    unsigned char shaResult[32];
    unsigned char* keyAndIv = new unsigned char[_keyLength+16];
    
    memcpy(keyAndIv, _key, _keyLength);
    memcpy(keyAndIv+_keyLength, _iv, 16);
    
    SHA256(keyAndIv, _keyLength+16, shaResult);
    memcpy(_key, shaResult, _keyLength);

	delete[] keyAndIv;

    return reinterpret_cast<char*>(crypted);
}

char* RC4Cipher::decrypt(const char* Data, std::size_t& length) {
    RC4_KEY rc4Key;
    RC4_set_key(&rc4Key, _keyLength, _keyDecrypt);

    unsigned char * crypted = new unsigned char[length];
    RC4(&rc4Key, length, reinterpret_cast<const unsigned char*>(Data), crypted);
    
    // Calculate a new key which is SHA1(concat(key, iv))
    unsigned char shaResult[32];
    unsigned char* keyAndIv = new unsigned char[_keyLength+16];
    
    memcpy(keyAndIv, _keyDecrypt, _keyLength);
    memcpy(keyAndIv+_keyLength, _ivDecrypt, 16);
    
    SHA256(keyAndIv, _keyLength+16, shaResult);
    memcpy(_keyDecrypt, shaResult, _keyLength);

	delete[] keyAndIv;

    return reinterpret_cast<char*>(crypted);
}

} // namespace ssf
