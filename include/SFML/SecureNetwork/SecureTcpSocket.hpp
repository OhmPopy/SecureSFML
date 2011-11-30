#ifndef __H_SECURESOCKET
#define __H_SECURESOCKET

#include <SFML/Network.hpp>
#include <openssl/rsa.h>
#include "Cipher.hpp"
#include "SecurePacket.hpp"

namespace sf {

  /**
   * A secure TCP socket that uses encryption for data transfers. Currently supported modes : 
   * RSA-RC4 (50->2048bits RC4 key size)
   * RSA-AES (128/192/256 bits AES key size)
   * NOTE : At the moment, the rsa key size is 2048 bits. It will be a parameter in future versions
   * Please take care to check the law in your country for maximum allowed key size.
   */

class SecureTcpSocket : public TcpSocket {

public:

    /**
     * Initializes a SecureTcpSocket object.
     * @param cipher the cipher to be used. This parameter should be set only server-side.
     * Server-side : defaults is an RC4 cipher with 128b random key
     */
    SecureTcpSocket(Cipher* cipher = 0) : keyPair(0), myCipher(cipher) { }
    
    ~SecureTcpSocket() { 
      
      if(myCipher)
        delete myCipher;

      if(keyPair)
        RSA_free(keyPair);

    }
    
  Socket::Status Connect(const IpAddress& HostAddress, short unsigned int Port, Uint32 timeout = 0);

    /**
     * Creates a new secure packet that will use the cipher of this secure socket for encryption/decryption
     */
    SecurePacket getNewSecurePacket();

private:

  friend class SecureTcpListener;

    RSA* keyPair;
    Cipher* myCipher;

    BIGNUM* receiveBigNum(int sixtyFourBits, Packet& data);
    void InitServerSide();
    void InitClientSide();

};

} // namespace sf

#endif
