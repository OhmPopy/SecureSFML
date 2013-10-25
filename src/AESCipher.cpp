#include "AESCipher.hpp"
#include <openssl/aes.h>

namespace ssf {

char* AESCipher::encrypt(const char* Data, int& length) {
  AES_KEY encryptKey;

  AES_set_encrypt_key(_key, _keyLength*8, &encryptKey);

  int newLength = length+getMissingBytes(length);
  unsigned char * crypted = new unsigned char[newLength];
  unsigned char tmpIv[16];
  unsigned char tmpXor[16];
  memcpy(tmpIv, _iv, 16);
  
  for(int i = 0; i < newLength/16; ++i) {
    // First step of CBC : XoR the plain block with the IV
    for(unsigned int j = 0; j < 16; ++j)
      if(i*16+j < length)
         tmpXor[j] = tmpIv[j]^Data[i*16+j];
      else
         tmpXor[j] = tmpIv[j];
       
    // Then encrypt the block
    AES_encrypt(tmpXor, &crypted[i*16], &encryptKey);
    
    // New "IV" is the block we just encrypted
    memcpy(tmpIv, &crypted[i*16], 16);
  }
  
  length = newLength;

  return reinterpret_cast<char*>(crypted);
}

int AESCipher::getMissingBytes(int length) {
  return 16-(length%16);
}

char* AESCipher::decrypt(const char* Data, int length) {
   AES_KEY decryptKey;

   AES_set_decrypt_key(_key, _keyLength*8, &decryptKey); 

   unsigned char * decrypted = new unsigned char[length];
   unsigned char tmpIv[16];
   unsigned char tmpXor[16];

   for(int i = (length/16)-1; i >= 0 ; --i) {
      AES_decrypt(reinterpret_cast<const unsigned char*>(&Data[i*16]), &decrypted[i*16], &decryptKey);
 
      if(i == 0)
         memcpy(tmpIv, _iv, 16);
      else
         memcpy(tmpIv, &Data[(i-1)*16], 16);
 
      for(unsigned int j = 0; j < 16; ++j)   
         decrypted[i*16+j] = decrypted[i*16+j]^tmpIv[j];
 
   }
  
  return reinterpret_cast<char*>(decrypted);
}

} // namespace ssf
