#ifndef __H_SECUREPACKET
#define __H_SECUREPACKET

#include <SFML/Network.hpp>
#include "Cipher.hpp"

namespace ssf {

/**
 * A secure packet, whose data will be encrypted using a stream cipher
 */
  class SecurePacket : public sf::Packet {

public:

    virtual const void * 	onSend (std::size_t &size);

    virtual void 	onReceive (const void *data, std::size_t size);
    
private:

    friend class SecureTcpSocket;

    Cipher* myCipher;

    SecurePacket(Cipher* cipher) : myCipher(cipher) { }

};

} // namespace ssf

#endif
