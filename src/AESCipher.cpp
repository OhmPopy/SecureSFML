#include "AESCipher.hpp"
#include <openssl/aes.h>

#if defined __linux__
    #include <arpa/inet.h>
#else
    #include <Winsock2.h>
#endif

namespace ssf {

char* AESCipher::encrypt(const char* Data, std::size_t& length) {
  AES_KEY encryptKey;

  AES_set_encrypt_key(_key, _keyLength*8, &encryptKey);

  unsigned int oldLength = htonl(length);
  int newLength = length+getMissingBytes(length);
  
  unsigned char * final = new unsigned char[newLength+sizeof(unsigned int)];
  unsigned char * crypted = final+sizeof(unsigned int);
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

  memcpy(final, &oldLength, sizeof(unsigned int));
  length = newLength+sizeof(unsigned int);
  
  return reinterpret_cast<char*>(final);
}

int AESCipher::getMissingBytes(int length) {
  return 16-(length%16);
}

char* AESCipher::decrypt(const char* Data, std::size_t& length) {

    if(length <= 16) {
        length = 0;
        return 0;
    }

   AES_KEY decryptKey;

   AES_set_decrypt_key(_key, _keyLength*8, &decryptKey); 

   unsigned char * decrypted = new unsigned char[length];
   const char * dataStart = Data+sizeof(unsigned int);
   unsigned char tmpIv[16];
   unsigned char tmpXor[16];

   for(int i = (length/16)-1; i >= 0 ; --i) {
      AES_decrypt(reinterpret_cast<const unsigned char*>(&dataStart[i*16]), &decrypted[i*16], &decryptKey);
 
      if(i == 0)
         memcpy(tmpIv, _iv, 16);
      else
         memcpy(tmpIv, &dataStart[(i-1)*16], 16);
 
      for(unsigned int j = 0; j < 16; ++j)
         decrypted[i*16+j] = decrypted[i*16+j]^tmpIv[j];
 
   }

    unsigned int newLength = ntohl(*(reinterpret_cast<const unsigned int*>(Data)));
    if(newLength > length) {
        delete[] decrypted;
        length = 0;
        return 0;
    }
    
    length = newLength;
    
    return reinterpret_cast<char*>(decrypted);
}

} // namespace ssf
