#include "SecurePacket.hpp"
#include <string.h>

namespace ssf {

const void* SecurePacket::onSend(std::size_t& DataSize) {
    DataSize = getDataSize();
    char* cryptedBuffer = myCipher->encrypt(static_cast<const char*>(getData()), DataSize);

    return cryptedBuffer;
}

void SecurePacket::onReceive (const void *data, std::size_t size) {

    std::size_t newSize = size;
    char* decryptedBuffer = myCipher->decrypt((const char*)data, newSize);

    if(!newSize)
        return;
        
    append(decryptedBuffer, newSize);
    delete [] decryptedBuffer;
}

} // namespace ssf
