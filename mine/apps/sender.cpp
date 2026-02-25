#include "../include/s_aes.hpp"
#include "../include/m_rsa.hpp"
#include "../include/utils.hpp"
#include "../include/net_protocol.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/rand.h>

#pragma comment(lib, "ws2_32.lib")

struct TransmissionPayload {
    std::vector<uint8_t> iv;
    std::vector<uint8_t> encryptedAesKey;
    std::vector<uint8_t> encryptedData;
};

class SenderNode {
    std::vector<uint8_t> public_n;
    std::vector<uint8_t> public_e;
public:
    SenderNode(const std::vector<uint8_t>& n, const std::vector<uint8_t>& e)
        : public_n(n), public_e(e) {}

    TransmissionPayload transmitData(const std::vector<uint8_t>& data) {
        TransmissionPayload payload;
        std::vector<uint8_t> K(16);
        std::vector<uint8_t> iv(16);
        RAND_bytes(K.data(), 16);
        RAND_bytes(iv.data(), 16);
        
        payload.encryptedAesKey = MRSA::encrypt(K, public_n, public_e);
        
        SAES aes(K);
        std::vector<uint8_t> paddedData = data;
        Utils::addPKCS7Padding(paddedData, 16);
        payload.encryptedData = aes.encrypt(paddedData, iv);
        payload.iv = iv;
        
        return payload;
    }
};

int main() {
    // Setup Winsock Client
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection to server failed." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    // Receive public key from receiver
    uint32_t nSize, eSize;
    recv(clientSocket, reinterpret_cast<char*>(&nSize), sizeof(nSize), 0);
    std::vector<uint8_t> tpk_n(nSize);
    recv(clientSocket, reinterpret_cast<char*>(tpk_n.data()), nSize, 0);
    
    recv(clientSocket, reinterpret_cast<char*>(&eSize), sizeof(eSize), 0);
    std::vector<uint8_t> tpk_e(eSize);
    recv(clientSocket, reinterpret_cast<char*>(tpk_e.data()), eSize, 0);

    std::cout << "Sender: Received Public Key (N: " << nSize << " chars, E: " << eSize << " chars)." << std::endl;

    SenderNode edgeDevice(tpk_n, tpk_e);
    std::vector<uint8_t> sensorData = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"

    TransmissionPayload payload;
    try {
        payload = edgeDevice.transmitData(sensorData);
    } catch (const std::exception& e) {
        std::cerr << "Encryption failed: " << e.what() << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    // Serialize and Send Data
    PayloadHeader header;
    header.encKeySize = static_cast<uint32_t>(payload.encryptedAesKey.size());
    header.encDataSize = static_cast<uint32_t>(payload.encryptedData.size());
    std::memcpy(header.iv, payload.iv.data(), 16);

    std::vector<uint8_t> netBuffer;
    netBuffer.resize(sizeof(PayloadHeader) + header.encKeySize + header.encDataSize);
    
    std::memcpy(netBuffer.data(), &header, sizeof(PayloadHeader));
    std::memcpy(netBuffer.data() + sizeof(PayloadHeader), payload.encryptedAesKey.data(), header.encKeySize);
    std::memcpy(netBuffer.data() + sizeof(PayloadHeader) + header.encKeySize, payload.encryptedData.data(), header.encDataSize);

    send(clientSocket, reinterpret_cast<const char*>(netBuffer.data()), netBuffer.size(), 0);
    std::cout << "Sender: MRA Payload transmitted successfully. Total bytes: " << netBuffer.size() << std::endl;

    closesocket(clientSocket);
    WSACleanup();
    return 0;
}