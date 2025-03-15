#include "modules/logging/logging_module.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <yaml-cpp/yaml.h>
#include <filesystem>

namespace security_agent {
namespace logging {

LoggingModule::LoggingModule(const std::string& config_path)
    : config_path_(config_path) {
    loadConfig();
    
    // Logs dizinini oluştur
    if (config_.file_logging && !config_.default_log_file.empty()) {
        std::filesystem::path log_path(config_.default_log_file);
        std::filesystem::create_directories(log_path.parent_path());
        
        // Tam yolu al
        std::string full_path = std::filesystem::absolute(log_path).string();
        config_.default_log_file = full_path;
        
        // Log dosyasını aç
        std::ofstream log_file(full_path, std::ios::app);
        if (log_file.is_open()) {
            log_file << "[" << getCurrentTimestamp() << "] [INFO] [LoggingModule] [constructor] Logging module initialized" << std::endl;
            log_file.close();
            std::cout << "Log file opened: " << full_path << std::endl;
        } else {
            std::cerr << "Failed to open log file: " << full_path << std::endl;
        }
    } else {
        std::cerr << "File logging disabled or no log file specified" << std::endl;
    }
}

LoggingModule::~LoggingModule() {
    // Dosya akışlarını kapat
    for (auto& stream : log_streams_) {
        if (stream.second.is_open()) {
            stream.second.close();
        }
    }
}

void LoggingModule::log(
    LogLevel level,
    const std::string& module,
    const std::string& function,
    const std::string& message,
    const std::string& file,
    const std::string& func,
    const std::string& line,
    const std::optional<nlohmann::json>& data
) {
    // Modül günlüğü etkin değilse, çık
    if (!isModuleLoggingEnabled(module)) {
        return;
    }
    
    // Log seviyesi yeterli değilse, çık
    if (static_cast<int>(level) < static_cast<int>(config_.min_level)) {
        return;
    }
    
    // Zaman damgası oluştur
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count() % 1000;
    
    std::stringstream timestamp_ss;
    timestamp_ss << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S");
    timestamp_ss << '.' << std::setfill('0') << std::setw(3) << now_ms;
    
    // Log mesajı oluştur
    std::stringstream log_ss;
    log_ss << "[" << timestamp_ss.str() << "] ";
    log_ss << "[" << getLevelString(level) << "] ";
    log_ss << "[" << module << "] ";
    log_ss << "[" << function << "] ";
    log_ss << message;
    
    if (data) {
        log_ss << " - Data: " << data->dump();
    }
    
    // Konsola yaz
    if (config_.console_logging) {
        std::cout << log_ss.str() << std::endl;
    }
    
    // Dosyaya yaz
    if (config_.file_logging && !config_.default_log_file.empty()) {
        try {
            // Dizin oluştur
            std::filesystem::path file_path(config_.default_log_file);
            std::filesystem::create_directories(file_path.parent_path());
            
            // Dosyaya yaz
            std::ofstream log_file(config_.default_log_file, std::ios::app);
            if (log_file.is_open()) {
                log_file << log_ss.str() << std::endl;
                log_file.close();
            } else {
                std::cerr << "Failed to open log file for writing: " << config_.default_log_file << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error writing to log file: " << e.what() << std::endl;
        }
    }
    
    // Sistem günlüğüne yaz
    if (config_.syslog_logging) {
        // TODO: Sistem günlüğüne yazma işlemi
    }
}

void LoggingModule::reloadConfig() {
    // Dosya akışlarını kapat
    for (auto& stream : log_streams_) {
        if (stream.second.is_open()) {
            stream.second.close();
        }
    }
    
    // Akışları temizle
    log_streams_.clear();
    
    // Yapılandırmayı yeniden yükle
    loadConfig();
}

bool LoggingModule::isModuleLoggingEnabled(const std::string& module) const {
    // Modül listesi boşsa, tüm modüller etkin
    if (config_.modules.empty()) {
        return true;
    }
    
    // Modül listesinde varsa, etkin
    return config_.modules.find(module) != config_.modules.end();
}

std::optional<std::string> LoggingModule::getModuleLogFile(const std::string& module) const {
    // Modül için özel dosya varsa, onu kullan
    auto it = config_.module_files.find(module);
    if (it != config_.module_files.end()) {
        return it->second;
    }
    
    // Varsayılan dosya varsa, onu kullan
    if (!config_.default_log_file.empty()) {
        return config_.default_log_file;
    }
    
    // Dosya yok
    return std::nullopt;
}

std::string LoggingModule::getLevelString(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE:
            return "TRACE";
        case LogLevel::DEBUG:
            return "DEBUG";
        case LogLevel::INFO:
            return "INFO";
        case LogLevel::WARNING:
            return "WARNING";
        case LogLevel::ERROR:
            return "ERROR";
        case LogLevel::CRITICAL:
            return "CRITICAL";
        default:
            return "UNKNOWN";
    }
}

void LoggingModule::loadConfig() {
    try {
        YAML::Node config = YAML::LoadFile(config_path_);
        auto logging_config = config["logging_module"];
        
        // Temel yapılandırma
        config_.enabled = logging_config["enabled"] ? logging_config["enabled"].as<bool>() : true;
        config_.console_logging = logging_config["console_logging"] ? logging_config["console_logging"].as<bool>() : true;
        config_.file_logging = logging_config["file_logging"] ? logging_config["file_logging"].as<bool>() : true;
        config_.syslog_logging = logging_config["syslog_logging"] ? logging_config["syslog_logging"].as<bool>() : false;
        config_.daily_rotation = logging_config["daily_rotation"] ? logging_config["daily_rotation"].as<bool>() : true;
        
        // Log seviyesi
        std::string min_level = logging_config["log_level"] ? logging_config["log_level"].as<std::string>() : "INFO";
        if (min_level == "TRACE") {
            config_.min_level = LogLevel::TRACE;
        } else if (min_level == "DEBUG") {
            config_.min_level = LogLevel::DEBUG;
        } else if (min_level == "INFO") {
            config_.min_level = LogLevel::INFO;
        } else if (min_level == "WARNING") {
            config_.min_level = LogLevel::WARNING;
        } else if (min_level == "ERROR") {
            config_.min_level = LogLevel::ERROR;
        } else if (min_level == "CRITICAL") {
            config_.min_level = LogLevel::CRITICAL;
        } else {
            config_.min_level = LogLevel::INFO;
        }
        
        // Varsayılan log dosyası
        config_.default_log_file = logging_config["log_file"] ? 
            logging_config["log_file"].as<std::string>() : "logs/security_agent.log";
        
        // Modül listesi
        if (logging_config["modules"]) {
            for (const auto& module : logging_config["modules"]) {
                config_.modules.insert(module.as<std::string>());
            }
        }
        
        // Modül dosyaları
        if (logging_config["module_files"]) {
            for (const auto& module_file : logging_config["module_files"]) {
                std::string module = module_file.first.as<std::string>();
                std::string file = module_file.second.as<std::string>();
                config_.module_files[module] = file;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error loading logging config: " << e.what() << std::endl;
        
        // Varsayılan değerler
        config_.enabled = true;
        config_.console_logging = true;
        config_.file_logging = true;
        config_.syslog_logging = false;
        config_.daily_rotation = true;
        config_.min_level = LogLevel::INFO;
        config_.default_log_file = "logs/security_agent.log";
    }
}

std::string LoggingModule::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count() % 1000;
    
    std::stringstream timestamp_ss;
    timestamp_ss << std::put_time(std::localtime(&now_time_t), "%Y-%m-%d %H:%M:%S");
    timestamp_ss << '.' << std::setfill('0') << std::setw(3) << now_ms;
    
    return timestamp_ss.str();
}

} // namespace logging
} // namespace security_agent 