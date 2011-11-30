#include "SFML/SecureNetwork/SecureTcpSocket.hpp"
#include "SFML/SecureNetwork/RC4Cipher.hpp"
#include "SFML/SecureNetwork/AESCipher.hpp"
#include <iostream>
#include <string.h>

using namespace std;

namespace sf {

Socket::Status SecureTcpSocket::Connect(const IpAddress& HostAddress, short unsigned int Port, Uint32 timeout) {

  if(TcpSocket::Connect(HostAddress, Port, timeout) == sf::Socket::Done) {
        InitClientSide();
    }

}

BIGNUM* SecureTcpSocket::receiveBigNum(int sixtyFourBits, Packet& data) {
    BIGNUM* bn = new BIGNUM;
    data >> bn->dmax;
    data >> bn->top;

    #ifdef THIRTY_TWO_BIT
    if(sixtyFourBits) {
      bn->dmax *= 2;
      bn->top *= 2;
    } 
    #endif

    data >> bn->neg;
    data >> bn->flags;
    bn->d = new BN_ULONG[bn->dmax];
    for(int i = 0; i < bn->dmax; ++i) {
      #if defined(SIXTY_FOUR_BIT_LONG) || defined (SIXTY_FOUR_BIT)
        BN_ULONG d;
        unsigned int firstPart;
        unsigned int secondPart;
        data >> firstPart;
        d = firstPart;
        d = d << 32;
        data >> secondPart;
        d += secondPart;
        bn->d[i] = d;
      #else
        data >> bn->d[i];
      #endif
    }

    return bn;
}

void SecureTcpSocket::InitServerSide() {

    /* default to RC4-128 when no cipher is set */
    if(!myCipher)
        myCipher = new RC4Cipher;

    Packet data;
    Receive(data);

    int sixtyFourBits;

    keyPair = RSA_new();

    data >> sixtyFourBits;

    keyPair->n = receiveBigNum(sixtyFourBits, data);
    keyPair->e = receiveBigNum(sixtyFourBits, data);

    unsigned char* cryptedCipherKey = new unsigned char[RSA_size(keyPair)];
    RSA_public_encrypt(myCipher->getKeyLength(), myCipher->getKey(), cryptedCipherKey, keyPair, RSA_PKCS1_OAEP_PADDING);

    Packet keyToSend;

    keyToSend << myCipher->getKeyLength();
    keyToSend << (int)myCipher->getCipherType();
    keyToSend.Append(cryptedCipherKey, RSA_size(keyPair));
    
    Send(keyToSend);
}

void SecureTcpSocket::InitClientSide() {
    keyPair = RSA_generate_key(2048, 17, 0, 0);

    if(myCipher)
      delete myCipher;

    sf::Packet data;

    #ifdef SIXTY_FOUR_BIT_LONG
    data << 1;
    #else
    data << 0;
    #endif

    data << keyPair->n->dmax;
    data << keyPair->n->top;
    data << keyPair->n->neg;
    data << keyPair->n->flags;
    for(int i = 0; i < keyPair->n->dmax; ++i) {
        #ifdef SIXTY_FOUR_BIT_LONG
        data << static_cast<unsigned int>(keyPair->n->d[i] >> 32);
        #endif
        data << static_cast<unsigned int>(keyPair->n->d[i]);
    }

    data << keyPair->e->dmax;
    data << keyPair->e->top;
    data << keyPair->e->neg;
    data << keyPair->e->flags;
    for(int i = 0; i < keyPair->e->dmax; ++i) {
        #ifdef SIXTY_FOUR_BIT_LONG
        data << static_cast<unsigned int>(keyPair->e->d[i] >> 32);
        #endif
        data << static_cast<unsigned int>(keyPair->e->d[i]);
    }
    Send(data);

    sf::Packet keyToReceive;
    int keyLength;
    int cipherType;

    Receive(keyToReceive);

    keyToReceive >> keyLength;
    keyToReceive >> cipherType;

    unsigned char* cryptedKey = new unsigned char[256];
    unsigned char* key = new unsigned char[keyLength];

    memcpy(cryptedKey, &keyToReceive.GetData()[8], 256);

    RSA_private_decrypt(256, cryptedKey, key, keyPair, RSA_PKCS1_OAEP_PADDING);

    switch(cipherType) {
    case CIPHER_RC4:
      myCipher = new RC4Cipher(keyLength, key);
      break;
    case CIPHER_AES:
      myCipher = new AESCipher(keyLength, key);
      break; 
    default:
      cerr << "Cipher inconnu !" << endl;
    }

    delete cryptedKey;
}

SecurePacket SecureTcpSocket::getNewSecurePacket() {
  return SecurePacket(myCipher);
}

} // namespace sf
