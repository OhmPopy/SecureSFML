#include "SecureSFML/SecureNetwork/AESCipher.hpp"
#include <openssl/aes.h>

namespace ssf {

char* AESCipher::encrypt(const char* Data, int& length) {
  AES_KEY encryptKey;

  AES_set_encrypt_key(_key, _keyLength*8, &encryptKey);

  length = length+getMissingBytes(length);
  unsigned char * crypted = new unsigned char[length];
  
  for(int i = 0; i < length/16; ++i)
    AES_encrypt(reinterpret_cast<const unsigned char*>(&Data[i*16]), &crypted[i*16], &encryptKey);

  return reinterpret_cast<char*>(crypted);
}

int AESCipher::getMissingBytes(int length) {
  return 16-(length%16);
}

char* AESCipher::decrypt(const char* Data, int length) {
   AES_KEY decryptKey;

   AES_set_decrypt_key(_key, _keyLength*8, &decryptKey); 

  length = length+getMissingBytes(length);

  unsigned char * decrypted = new unsigned char[length];
  
  for(int i = 0; i < length/16; ++i)
    AES_decrypt(reinterpret_cast<const unsigned char*>(&Data[i*16]), &decrypted[i*16], &decryptKey);
  return reinterpret_cast<char*>(decrypted);
}

} // namespace ssf
