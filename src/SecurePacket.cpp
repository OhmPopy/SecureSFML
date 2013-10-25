#include "SecurePacket.hpp"
#include <string.h>

namespace ssf {

const void* SecurePacket::onSend(std::size_t& DataSize) {
    char* myBuffer = new char[getDataSize()];
    memcpy(myBuffer, getData(), getDataSize());

    int size = getDataSize();
    char* cryptedBuffer = myCipher->encrypt(myBuffer, size);
    DataSize = size;
    
    delete[] myBuffer;

    return cryptedBuffer;
}

void SecurePacket::onReceive (const void *data, std::size_t size) {
    char* decryptedBuffer = myCipher->decrypt((const char*)data, size);

    append(decryptedBuffer, size);
}

} // namespace ssf
