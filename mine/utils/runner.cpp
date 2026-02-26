#include <windows.h>
#include <iostream>
#include <chrono>
#include <string>

std::string getAppsPath() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string path(buffer);
    size_t pos = path.find_last_of("\\/");
    if (pos != std::string::npos) {
        path = path.substr(0, pos); // utils
        pos = path.find_last_of("\\/");
        if (pos != std::string::npos) {
            path = path.substr(0, pos); // benchmark
            return path + "\\apps";
        }
    }
    return ".\\apps";
}

int main() {
    std::string appsPath = getAppsPath();
    std::string receiverShell = appsPath + "\\receiver.exe";
    std::string senderShell = appsPath + "\\sender.exe";

    char recCmd[MAX_PATH];
    strcpy(recCmd, receiverShell.c_str());
    char senCmd[MAX_PATH];
    strcpy(senCmd, senderShell.c_str());

    STARTUPINFOA siReceiver = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION piReceiver;

    STARTUPINFOA siSender = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION piSender;

    std::cout << "[Runner] Starting Receiver node from " << receiverShell << std::endl;

    // Start Receiver
    if (!CreateProcessA(NULL, recCmd, NULL, NULL, FALSE, 0, NULL, appsPath.c_str(), &siReceiver, &piReceiver)) {
        DWORD err = GetLastError();
        std::cerr << "[Runner] Failed to start receiver. Error: " << err << std::endl;
        return 1;
    }

    std::cout << "[Runner] Waiting for receiver to generate keys and listen (5 seconds)..." << std::endl;
    Sleep(5000); // Wait for the receiver to generate its keys and start listening

    std::cout << "[Runner] Starting Sender node and beginning timer..." << std::endl;

    auto startTime = std::chrono::high_resolution_clock::now();

    // Start Sender
    if (!CreateProcessA(NULL, senCmd, NULL, NULL, FALSE, 0, NULL, appsPath.c_str(), &siSender, &piSender)) {
        DWORD err = GetLastError();
        std::cerr << "[Runner] Failed to start sender. Error: " << err << std::endl;
        TerminateProcess(piReceiver.hProcess, 1);
        return 1;
    }

    // Wait for the Sender to finish sending
    WaitForSingleObject(piSender.hProcess, INFINITE);

    // Wait for the Receiver to finish receiving and decrypting
    WaitForSingleObject(piReceiver.hProcess, INFINITE);

    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = endTime - startTime;

    std::cout << "\n========================================================" << std::endl;
    std::cout << " Benchmark Results:" << std::endl;
    std::cout << " Time taken to start sender, encrypt, transmit," << std::endl;
    std::cout << " receive, and decrypt the data:" << std::endl;
    std::cout << " ===> " << duration.count() << " ms <===" << std::endl;
    std::cout << "========================================================\n" << std::endl;

    CloseHandle(piReceiver.hProcess);
    CloseHandle(piReceiver.hThread);
    CloseHandle(piSender.hProcess);
    CloseHandle(piSender.hThread);

    return 0;
}
