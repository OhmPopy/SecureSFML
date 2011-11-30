#ifndef __H_SECURETCPLISTENER
#define __H_SECURETCPLISTENER

#include <SFML/Network.hpp>
#include "SecureTcpSocket.hpp"

namespace sf {

class SecureTcpListener : public TcpListener {

public:
 
    Socket::Status Accept(SecureTcpSocket& Connected);

};

} // namespace sf

#endif
