// include/net_protocol.hpp
#ifndef NET_PROTOCOL_HPP
#define NET_PROTOCOL_HPP

#include <cstdint>

#pragma pack(push, 1) // Disable padding for direct socket transmission
struct PayloadHeader {
    uint32_t encKeySize;
    uint32_t encDataSize;
    uint8_t iv[16];
};
#pragma pack(pop)

#endif