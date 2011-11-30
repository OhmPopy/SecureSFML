#include "SFML/SecureNetwork/SecureTcpListener.hpp"

namespace sf {

Socket::Status SecureTcpListener::Accept(SecureTcpSocket& Connected) {
  Socket::Status s = TcpListener::Accept(Connected);
  if(s == Socket::Done)
    Connected.InitServerSide();

  return s;
}

} // namespace sf
