#include "../include/s_aes.hpp"
#include "../include/m_rsa.hpp"
#include "../include/utils.hpp"
#include "../include/net_protocol.hpp"
#include <winsock2.h>
#include <iostream>
#include <vector>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

struct TransmissionPayload {
    std::vector<uint8_t> iv;
    std::vector<uint8_t> encryptedAesKey;
    std::vector<uint8_t> encryptedData;
};

class ReceiverNode {
    TriplePrimeKey privateKey;
public:
    ReceiverNode(const TriplePrimeKey& key) : privateKey(key) {}

    std::vector<uint8_t> processReceivedData(const std::vector<uint8_t>& encKey, 
                                             const std::vector<uint8_t>& encData, 
                                             const std::vector<uint8_t>& iv) {
        std::vector<uint8_t> K = MRSA::decrypt(encKey, privateKey);
        // OpenSSL may leave leading zeros if output is exactly 16 bytes but sometimes less/more due to padding.
        // Assuming K is exactly 16 bytes for AES-128 if done raw:
        std::vector<uint8_t> paddedK(16, 0);
        if (K.size() <= 16) {
            std::memcpy(paddedK.data() + 16 - K.size(), K.data(), K.size());
        } else {
            std::memcpy(paddedK.data(), K.data() + K.size() - 16, 16);
        }
        
        SAES aes(paddedK);
        std::vector<uint8_t> paddedData = aes.decrypt(encData, iv);
        Utils::removePKCS7Padding(paddedData);
        return paddedData;
    }
};

int main() {
    TriplePrimeKey tpk = MRSA::generateKey(1024);
    ReceiverNode server(tpk);

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(8080);
    
    bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(serverSocket, 1);
    
    std::cout << "Receiver: Listening on port 8080..." << std::endl;
    struct sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    SOCKET clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
    std::cout << "Receiver: Connection established!" << std::endl;
    
    // Send public key (n and e) to sender
    uint32_t nSize = static_cast<uint32_t>(tpk.n.size());
    uint32_t eSize = static_cast<uint32_t>(tpk.e.size());
    send(clientSocket, reinterpret_cast<const char*>(&nSize), sizeof(nSize), 0);
    send(clientSocket, reinterpret_cast<const char*>(tpk.n.data()), nSize, 0);
    send(clientSocket, reinterpret_cast<const char*>(&eSize), sizeof(eSize), 0);
    send(clientSocket, reinterpret_cast<const char*>(tpk.e.data()), eSize, 0);
    std::cout << "Receiver: Public key sent." << std::endl;

    // Receive Payload Header
    PayloadHeader header;
    int bytesReceived = recv(clientSocket, reinterpret_cast<char*>(&header), sizeof(PayloadHeader), 0);
    
    if (bytesReceived == sizeof(PayloadHeader)) {
        std::vector<uint8_t> iv(header.iv, header.iv + 16);
        std::vector<uint8_t> encKey(header.encKeySize);
        std::vector<uint8_t> encData(header.encDataSize);

        // Receive Cryptographic Payloads
        int keyRecv = 0;
        while(keyRecv < header.encKeySize) {
            keyRecv += recv(clientSocket, reinterpret_cast<char*>(encKey.data() + keyRecv), header.encKeySize - keyRecv, 0);
        }
        
        int dataRecv = 0;
        while(dataRecv < header.encDataSize) {
            dataRecv += recv(clientSocket, reinterpret_cast<char*>(encData.data() + dataRecv), header.encDataSize - dataRecv, 0);
        }

        std::cout << "Receiver: Payload received. Key size: " << header.encKeySize 
                  << ", Data size: " << header.encDataSize << std::endl;

        // Decrypt
        try {
            std::vector<uint8_t> plaintext = server.processReceivedData(encKey, encData, iv);
            std::cout << "Receiver: Decrypted message - " << std::string(plaintext.begin(), plaintext.end()) << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Receiver: Decryption failure: " << e.what() << std::endl;
        }
    }
    
    closesocket(clientSocket);
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}