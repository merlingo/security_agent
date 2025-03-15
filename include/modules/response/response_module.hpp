#pragma once

#include "modules/event_management/event_manager.hpp"
#include "modules/event_management/event.hpp"
#include <string>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <queue>
#include <condition_variable>

namespace security_agent {
namespace response {

enum class ResponseAction {
    KILL_PROCESS,
    QUARANTINE,
    ERASE_FILE,
    TRANSFER_FILE,
    REBOOT
};

class ResponseModule {
public:
    ResponseModule(const std::string& config_path);
    ~ResponseModule();

    // Başlatma ve durdurma
    void start();
    void stop();

    // Response fonksiyonları
    bool killProcess(int target_pid);
    bool quarantineFile(const std::string& file_path);
    bool eraseFile(const std::string& file_path);
    bool transferFile(const std::string& file_path, const std::string& destination);
    bool reboot();

    // Test için
    void setEventManager(std::shared_ptr<event_management::EventManager> event_manager) {
        event_manager_ = event_manager;
    }

private:
    // Event işleme
    void processEvent(const event_management::Event& event);
    void eventLoop();

    // Yardımcı fonksiyonlar
    bool authorizeAction(ResponseAction action);
    void logAction(const std::string& action, bool success, const std::string& error = "");
    void sendResponseEvent(const std::string& action, bool success, const std::string& error = "");

    // Yapılandırma
    struct Config {
        bool enabled;
        std::string log_level;
        std::string quarantine_folder;
        std::string rabbitmq_host;
        int rabbitmq_port;
        std::string rabbitmq_queue;
        std::unordered_map<std::string, bool> enabled_actions;
    };

    void loadConfig(const std::string& config_path);

    // Üye değişkenleri
    std::shared_ptr<event_management::EventManager> event_manager_;
    Config config_;
    bool running_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::queue<event_management::Event> event_queue_;
    std::unique_ptr<std::thread> event_thread_;
};

} // namespace response
} // namespace security_agent 