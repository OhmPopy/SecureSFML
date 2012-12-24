#ifndef __H_SECURETCPLISTENER
#define __H_SECURETCPLISTENER

#include <SFML/Network.hpp>
#include "SecureTcpSocket.hpp"

namespace ssf {

class SecureTcpListener : public sf::TcpListener {

public:
 
    Socket::Status accept(SecureTcpSocket& Connected);

};

} // namespace ssf

#endif
