#include "SecureSFML/SecureNetwork/SecureTcpListener.hpp"

using namespace sf;

namespace ssf {

Socket::Status SecureTcpListener::Accept(SecureTcpSocket& Connected) {
  Socket::Status s = TcpListener::Accept(Connected);
  if(s == Socket::Done)
    Connected.InitServerSide();

  return s;
}

} // namespace ssf
