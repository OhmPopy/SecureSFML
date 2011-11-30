#include "SFML/SecureNetwork/SecurePacket.hpp"
#include <string.h>

namespace sf {

const char* SecurePacket::OnSend(std::size_t& DataSize) {
    char* myBuffer = new char[GetDataSize()];
    memcpy(myBuffer, GetData(), GetDataSize());

    int size = GetDataSize();
    char* cryptedBuffer = myCipher->encrypt(myBuffer, size);
    DataSize = size;
    
    delete myBuffer;

    return cryptedBuffer;
}

void SecurePacket::OnReceive(const char* Data, std::size_t DataSize) {
    char* decryptedBuffer = myCipher->decrypt(Data, DataSize);

    Append(decryptedBuffer, DataSize);
}

} // namespace sf
