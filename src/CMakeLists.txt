include_directories(../include)

add_library(sfml-network-secure SHARED SecureTcpSocket.cpp SecurePacket.cpp RC4Cipher.cpp AESCipher.cpp SecureTcpListener.cpp)
target_link_libraries(sfml-network-secure crypto sfml-system sfml-network)

SET_TARGET_PROPERTIES(sfml-network-secure
                      PROPERTIES
                      VERSION 1.0.0
                      SOVERSION 1)

INSTALL(TARGETS sfml-network-secure
        DESTINATION lib)
