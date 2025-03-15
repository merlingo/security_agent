#include "modules/response/response_module.hpp"
#include "modules/logging/logging_module.hpp"
#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

std::atomic<bool> running(true);

void signalHandler(int signum) {
    std::cout << "Signal " << signum << " received. Shutting down..." << std::endl;
    running = false;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    try {
        // Logging modülünü başlat
        auto logging_module = std::make_shared<security_agent::logging::LoggingModule>(argv[1]);
        
        // Başlangıç log mesajı
        logging_module->log(
            security_agent::logging::LogLevel::INFO,
            "Main",
            "main",
            "Security Agent başlatılıyor",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
        
        std::cout << "Security Agent başlatıldı. Çıkmak için Ctrl+C tuşlarına basın." << std::endl;
        
        // Her 5 saniyede bir log mesajı
        int counter = 0;
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            counter++;
            
            // Periyodik log mesajı
            logging_module->log(
                security_agent::logging::LogLevel::INFO,
                "Main",
                "main",
                "Security Agent çalışıyor - " + std::to_string(counter) + ". kontrol",
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
        
        // Kapanış log mesajı
        logging_module->log(
            security_agent::logging::LogLevel::INFO,
            "Main",
            "main",
            "Security Agent kapatılıyor",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 