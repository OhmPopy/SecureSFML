#include "SFML/SecureNetwork/RC4Cipher.hpp"
#include <openssl/rc4.h>

namespace sf {

char* RC4Cipher::encrypt(const char* Data, int& length) {

    RC4_KEY rc4Key;
    RC4_set_key(&rc4Key, _keyLength, _key);

    unsigned char * crypted = new unsigned char[length];
    RC4(&rc4Key, length, reinterpret_cast<const unsigned char*>(Data), crypted);

    return reinterpret_cast<char*>(crypted);
}

char* RC4Cipher::decrypt(const char* Data, int length) {
    return encrypt(Data, length);
}

} // namespace sf
