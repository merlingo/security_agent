#include "modules/response/response_module.hpp"
#include <yaml-cpp/yaml.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <chrono>

namespace security_agent {
namespace response {

ResponseModule::ResponseModule(const std::string& config_path)
    : running_(false) {
    loadConfig(config_path);
    
    if (!config_.enabled) {
        throw std::runtime_error("Response module is disabled in configuration");
    }
    
    // Event manager'ı başlat
    event_manager_ = std::make_shared<event_management::EventManager>(
        config_.rabbitmq_host,
        config_.rabbitmq_port,
        "guest",  // Varsayılan kullanıcı adı
        "guest",  // Varsayılan şifre
        "/",      // Varsayılan vhost
        false     // SSL kullanma
    );
}

ResponseModule::~ResponseModule() {
    stop();
}

void ResponseModule::start() {
    if (running_) {
        return;
    }

    running_ = true;
    event_thread_ = std::make_unique<std::thread>(&ResponseModule::eventLoop, this);

    // Response eventlerini dinlemeye başla
    auto callback = [this](const event_management::Event& event) {
        std::lock_guard<std::mutex> lock(mutex_);
        event_queue_.push(event);
        condition_.notify_one();
    };

    event_manager_->subscribe(
        config_.rabbitmq_queue,
        "response_exchange",
        "response.#",
        callback
    );
}

void ResponseModule::stop() {
    if (!running_) {
        return;
    }

    running_ = false;
    condition_.notify_all();

    if (event_thread_ && event_thread_->joinable()) {
        event_thread_->join();
    }
}

bool ResponseModule::killProcess(int target_pid) {
    if (!authorizeAction(ResponseAction::KILL_PROCESS)) {
        logAction("kill_process", false, "Action not authorized");
        return false;
    }

    try {
        // Önce normal sonlandırma dene
        if (kill(target_pid, SIGTERM) == 0) {
            // 5 saniye bekle
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            // Hala çalışıyorsa zorla sonlandır
            if (kill(target_pid, 0) == 0) {
                kill(target_pid, SIGKILL);
            }
        }

        logAction("kill_process", true);
        sendResponseEvent("kill_process", true);
        return true;
    } catch (const std::exception& e) {
        logAction("kill_process", false, e.what());
        sendResponseEvent("kill_process", false, e.what());
        return false;
    }
}

bool ResponseModule::quarantineFile(const std::string& file_path) {
    if (!authorizeAction(ResponseAction::QUARANTINE)) {
        logAction("quarantine", false, "Action not authorized");
        return false;
    }

    try {
        std::filesystem::path source(file_path);
        std::filesystem::path dest(config_.quarantine_folder / source.filename());

        // Hedef klasör yoksa oluştur
        std::filesystem::create_directories(config_.quarantine_folder);

        // Dosyayı taşı
        std::filesystem::rename(source, dest);

        logAction("quarantine", true);
        sendResponseEvent("quarantine", true);
        return true;
    } catch (const std::exception& e) {
        logAction("quarantine", false, e.what());
        sendResponseEvent("quarantine", false, e.what());
        return false;
    }
}

bool ResponseModule::eraseFile(const std::string& file_path) {
    if (!authorizeAction(ResponseAction::ERASE_FILE)) {
        logAction("erase_file", false, "Action not authorized");
        return false;
    }

    try {
        // Dosyayı 3 kez üzerine yazarak sil
        std::ofstream file(file_path, std::ios::binary | std::ios::out);
        for (int i = 0; i < 3; ++i) {
            file.seekp(0);
            file << std::string(file.tellp(), 0);
        }
        file.close();

        std::filesystem::remove(file_path);

        logAction("erase_file", true);
        sendResponseEvent("erase_file", true);
        return true;
    } catch (const std::exception& e) {
        logAction("erase_file", false, e.what());
        sendResponseEvent("erase_file", false, e.what());
        return false;
    }
}

bool ResponseModule::transferFile(const std::string& file_path, const std::string& destination) {
    if (!authorizeAction(ResponseAction::TRANSFER_FILE)) {
        logAction("transfer_file", false, "Action not authorized");
        return false;
    }

    try {
        std::filesystem::path source(file_path);
        std::filesystem::path dest(destination);

        // Hedef klasör yoksa oluştur
        std::filesystem::create_directories(dest.parent_path());

        // Dosyayı kopyala
        std::filesystem::copy_file(source, dest, std::filesystem::copy_options::overwrite_existing);

        logAction("transfer_file", true);
        sendResponseEvent("transfer_file", true);
        return true;
    } catch (const std::exception& e) {
        logAction("transfer_file", false, e.what());
        sendResponseEvent("transfer_file", false, e.what());
        return false;
    }
}

bool ResponseModule::reboot() {
    if (!authorizeAction(ResponseAction::REBOOT)) {
        logAction("reboot", false, "Action not authorized");
        return false;
    }

    try {
        logAction("reboot", true, "System will reboot in 5 seconds");
        std::this_thread::sleep_for(std::chrono::seconds(1)); // Test için 1 saniye bekle
        
        #ifndef TESTING
        sync();
        ::reboot(0);
        #endif

        sendResponseEvent("reboot", true);
        return true;
    } catch (const std::exception& e) {
        logAction("reboot", false, e.what());
        sendResponseEvent("reboot", false, e.what());
        return false;
    }
}

void ResponseModule::processEvent(const event_management::Event& event) {
    try {
        const auto& payload = event.getPayload();
        const std::string action = payload["action"].get<std::string>();
        bool success = false;

        if (action == "kill_process") {
            success = killProcess(payload["target_pid"].get<int>());
        } else if (action == "quarantine") {
            success = quarantineFile(payload["file_path"].get<std::string>());
        } else if (action == "erase_file") {
            success = eraseFile(payload["file_path"].get<std::string>());
        } else if (action == "transfer_file") {
            success = transferFile(
                payload["file_path"].get<std::string>(),
                payload["destination"].get<std::string>()
            );
        } else if (action == "reboot") {
            success = reboot();
        } else {
            logAction(action, false, "Unknown action");
        }
    } catch (const std::exception& e) {
        logAction("process_event", false, e.what());
    }
}

void ResponseModule::eventLoop() {
    while (running_) {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this] {
            return !running_ || !event_queue_.empty();
        });

        if (!running_) {
            break;
        }

        auto event = event_queue_.front();
        event_queue_.pop();
        lock.unlock();

        processEvent(event);
    }
}

bool ResponseModule::authorizeAction(ResponseAction action) {
    // TODO: RBAC implementasyonu
    return true;
}

void ResponseModule::logAction(const std::string& action, bool success, const std::string& error) {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::string timestamp = std::ctime(&now_c);
    timestamp.pop_back(); // Remove newline

    std::cout << "[" << timestamp << "] "
              << (success ? "SUCCESS" : "FAILURE")
              << " - Action: " << action;
    if (!error.empty()) {
        std::cout << " - Error: " << error;
    }
    std::cout << std::endl;
}

void ResponseModule::sendResponseEvent(const std::string& action, bool success, const std::string& error) {
    nlohmann::json payload = {
        {"action", action},
        {"success", success},
        {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
    };

    if (!error.empty()) {
        payload["error"] = error;
    }

    event_management::Event event(
        event_management::EventType::RESPONSE_ACTION,
        "response_module",
        success ? event_management::SeverityLevel::INFO : event_management::SeverityLevel::WARNING,
        payload
    );

    event_manager_->publishEvent(event, "response_exchange", "response.result");
}

void ResponseModule::loadConfig(const std::string& config_path) {
    YAML::Node config = YAML::LoadFile(config_path);
    auto response_config = config["response_module"];

    config_.enabled = response_config["enabled"].as<bool>();
    config_.log_level = response_config["log_level"].as<std::string>();
    config_.quarantine_folder = response_config["quarantine_folder"].as<std::string>();
    config_.rabbitmq_host = response_config["rabbitmq"]["host"].as<std::string>();
    config_.rabbitmq_port = response_config["rabbitmq"]["port"].as<int>();
    config_.rabbitmq_queue = response_config["rabbitmq"]["queue"].as<std::string>();

    auto actions = response_config["actions"];
    config_.enabled_actions = {
        {"kill_process", actions["kill_process"].as<bool>()},
        {"quarantine", actions["quarantine"].as<bool>()},
        {"erase_file", actions["erase_file"].as<bool>()},
        {"transfer_file", actions["transfer_file"].as<bool>()},
        {"reboot", actions["reboot"].as<bool>()}
    };
}

} // namespace response
} // namespace security_agent 