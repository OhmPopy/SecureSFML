include_directories(../include ../include/SecureSFML/SecureNetwork)

add_library(secure-sfml SHARED SecureTcpSocket.cpp SecurePacket.cpp RC4Cipher.cpp AESCipher.cpp SecureTcpListener.cpp)
target_link_libraries(secure-sfml crypto sfml-system sfml-network)

SET_TARGET_PROPERTIES(secure-sfml
                      PROPERTIES
                      VERSION 1.0.0
                      SOVERSION 1)

INSTALL(TARGETS secure-sfml
        DESTINATION lib)
