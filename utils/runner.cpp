#include <windows.h>
#include <iostream>
#include <chrono>

int main() {
    STARTUPINFOA siReceiver = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION piReceiver;

    STARTUPINFOA siSender = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION piSender;

    std::cout << "[Runner] Starting Receiver node..." << std::endl;

    // Start Receiver
    if (!CreateProcessA(NULL, (LPSTR)".\\receiver.exe", NULL, NULL, FALSE, 0, NULL, NULL, &siReceiver, &piReceiver)) {
        std::cerr << "[Runner] Failed to start receiver. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[Runner] Waiting for receiver to generate keys and listen (5 seconds)..." << std::endl;
    Sleep(5000); // Wait for the receiver to generate its keys and start listening

    std::cout << "[Runner] Starting Sender node and beginning timer..." << std::endl;

    auto startTime = std::chrono::high_resolution_clock::now();

    // Start Sender
    if (!CreateProcessA(NULL, (LPSTR)".\\sender.exe", NULL, NULL, FALSE, 0, NULL, NULL, &siSender, &piSender)) {
        std::cerr << "[Runner] Failed to start sender. Error: " << GetLastError() << std::endl;
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
