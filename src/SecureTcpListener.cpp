#include "SecureSFML/SecureNetwork/SecureTcpListener.hpp"

using namespace sf;

namespace ssf {

Socket::Status SecureTcpListener::accept(SecureTcpSocket& Connected) {
  Socket::Status s = TcpListener::accept(Connected);
  if(s == Socket::Done)
    Connected.InitServerSide();

  return s;
}

} // namespace ssf
