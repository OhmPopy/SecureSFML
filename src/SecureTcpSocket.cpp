#include "SecureTcpSocket.hpp"
#include "RC4Cipher.hpp"
#include "AESCipher.hpp"
#include <iostream>
#include <string.h>

#include <openssl/pem.h>

using namespace std;
using namespace sf;

namespace ssf {

Socket::Status SecureTcpSocket::connect(const IpAddress& HostAddress, short unsigned int Port, sf::Time timeout) {

  Socket::Status s = TcpSocket::connect(HostAddress, Port, timeout);
  if(s == Socket::Done)
      InitClientSide();

  return s;

}

void SecureTcpSocket::InitServerSide() {
    /* default to RC4-128 when no cipher is set */
   if(!myCipher)
      myCipher = new RC4Cipher;

   Packet data;
   receive(data);

	BIO* cbio = BIO_new_mem_buf((void*)data.getData(), data.getDataSize());
	if(!PEM_read_bio_RSAPublicKey(cbio, &keyPair, NULL, NULL)) {
        cerr << "Couldn't read public key sent by peer" << endl;
        BIO_free_all(cbio);
        return;
    }


   BIO_free_all(cbio);
   unsigned char* cryptedCipherKey = new unsigned char[RSA_size(keyPair)];
   RSA_public_encrypt(myCipher->getKeyLength(), myCipher->getKey(), cryptedCipherKey, keyPair, RSA_PKCS1_OAEP_PADDING);

   unsigned char* cryptedIv = new unsigned char[RSA_size(keyPair)];
   RSA_public_encrypt(16, myCipher->getIv(), cryptedIv, keyPair, RSA_PKCS1_OAEP_PADDING);

   Packet keyToSend;

   keyToSend << myCipher->getKeyLength();
   keyToSend << (int)myCipher->getCipherType();
   keyToSend.append(cryptedCipherKey, RSA_size(keyPair));
   keyToSend.append(cryptedIv, RSA_size(keyPair));

   send(keyToSend);

   delete[] cryptedCipherKey;
   delete[] cryptedIv;
}

void SecureTcpSocket::InitClientSide() {
    keyPair = RSA_generate_key(2048, 65537, 0, 0);

    if(myCipher)
      delete myCipher;

    sf::Packet data;
    
	BIO *mem = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(mem, keyPair);

    unsigned char *rsaPem;
    unsigned short size = static_cast<unsigned short>(BIO_get_mem_data(mem, &rsaPem));

	data.append(rsaPem, size);

	BIO_free_all(mem);

    send(data);

    sf::Packet keyToReceive;
    int keyLength;
    int cipherType;

    receive(keyToReceive);

    keyToReceive >> keyLength;
    keyToReceive >> cipherType;

    unsigned char* cryptedKey = new unsigned char[RSA_size(keyPair)];
    unsigned char* cryptedIv = new unsigned char[RSA_size(keyPair)];
    
    unsigned char* key = new unsigned char[keyLength];
    unsigned char iv[16];
    
    const char* keyToReceiveData = (const char*)keyToReceive.getData();

    memcpy(cryptedKey, &keyToReceiveData[8], RSA_size(keyPair));
    memcpy(cryptedIv, &keyToReceiveData[8+RSA_size(keyPair)], RSA_size(keyPair));

    RSA_private_decrypt(RSA_size(keyPair), cryptedKey, key, keyPair, RSA_PKCS1_OAEP_PADDING);
    RSA_private_decrypt(RSA_size(keyPair), cryptedIv, iv, keyPair, RSA_PKCS1_OAEP_PADDING);

    switch(cipherType) {
    case CIPHER_RC4:
      myCipher = new RC4Cipher(keyLength, key, iv);
      break;
    case CIPHER_AES:
      myCipher = new AESCipher(keyLength, key, iv);
      break; 
    default:
      cerr << "Cipher inconnu !" << endl;
    }
    
    delete[] key;
	delete[] cryptedKey;
	delete[] cryptedIv;

}

SecurePacket SecureTcpSocket::getNewSecurePacket() {
  return SecurePacket(myCipher);
}

} // namespace ssf
