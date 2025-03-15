#include "modules/monitoring/syslog_monitoring.hpp"
#include "modules/event_management/event_manager.hpp"
#include "modules/logging/logging_module.hpp"
#include "modules/routing/routing_module.hpp"
#include "modules/detection/detection_module.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <openssl/evp.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <yaml-cpp/yaml.h>
#include <filesystem>
#include <chrono>
#include <iomanip>

namespace security_agent {
namespace monitoring {

// SyslogEntry sınıfı implementasyonu
nlohmann::json SyslogEntry::toJson() const {
    nlohmann::json json;
    json["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    json["facility"] = facility;
    json["severity"] = severity;
    json["hostname"] = hostname;
    json["process_name"] = process_name;
    json["pid"] = pid;
    json["message"] = message;
    json["source_file"] = source_file;
    json["user"] = user;
    
    return json;
}

std::string SyslogEntry::calculateHash() const {
    std::stringstream ss;
    ss << std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    ss << facility << severity << hostname << process_name << pid;
    ss << message << source_file << user;
    
    // EVP_Digest kullanarak MD5 hash hesapla
    unsigned char md5_hash[EVP_MAX_MD_SIZE];
    unsigned int md5_len = 0;
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, ss.str().c_str(), ss.str().length());
    EVP_DigestFinal_ex(mdctx, md5_hash, &md5_len);
    EVP_MD_CTX_free(mdctx);
    
    // Hash'i hex string'e dönüştür
    std::stringstream md5_ss;
    for (unsigned int i = 0; i < md5_len; i++) {
        md5_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md5_hash[i]);
    }
    
    return md5_ss.str();
}

// LogEvent sınıfı implementasyonu
nlohmann::json LogEvent::toJson() const {
    nlohmann::json json;
    json["log_entry"] = log_entry.toJson();
    
    // Olay türünü string'e dönüştür
    std::string event_type_str;
    switch (event_type) {
        case LogEventType::LOGIN_SUCCESS: event_type_str = "LOGIN_SUCCESS"; break;
        case LogEventType::LOGIN_FAILURE: event_type_str = "LOGIN_FAILURE"; break;
        case LogEventType::LOGOUT: event_type_str = "LOGOUT"; break;
        case LogEventType::ACCOUNT_CHANGE: event_type_str = "ACCOUNT_CHANGE"; break;
        case LogEventType::PRIVILEGE_ESCALATION: event_type_str = "PRIVILEGE_ESCALATION"; break;
        case LogEventType::PROCESS_START: event_type_str = "PROCESS_START"; break;
        case LogEventType::PROCESS_STOP: event_type_str = "PROCESS_STOP"; break;
        case LogEventType::SERVICE_START: event_type_str = "SERVICE_START"; break;
        case LogEventType::SERVICE_STOP: event_type_str = "SERVICE_STOP"; break;
        case LogEventType::SYSTEM_BOOT: event_type_str = "SYSTEM_BOOT"; break;
        case LogEventType::SYSTEM_SHUTDOWN: event_type_str = "SYSTEM_SHUTDOWN"; break;
        case LogEventType::FIREWALL_CHANGE: event_type_str = "FIREWALL_CHANGE"; break;
        case LogEventType::NETWORK_CHANGE: event_type_str = "NETWORK_CHANGE"; break;
        case LogEventType::FILE_ACCESS: event_type_str = "FILE_ACCESS"; break;
        case LogEventType::FILE_CHANGE: event_type_str = "FILE_CHANGE"; break;
        case LogEventType::CRON_JOB: event_type_str = "CRON_JOB"; break;
        case LogEventType::SECURITY_ALERT: event_type_str = "SECURITY_ALERT"; break;
        case LogEventType::OTHER: event_type_str = "OTHER"; break;
    }
    
    json["event_type"] = event_type_str;
    json["event_description"] = event_description;
    json["event_details"] = event_details;
    
    return json;
}

// SyslogMonitoring sınıfı implementasyonu
SyslogMonitoring::SyslogMonitoring(const std::string& config_path,
                                 std::shared_ptr<event_management::EventManager> event_manager,
                                 std::shared_ptr<logging::LoggingModule> logging_module,
                                 std::shared_ptr<routing::RoutingModule> routing_module,
                                 std::shared_ptr<detection::DetectionModule> detection_module)
    : MonitoringInterface(config_path, event_manager, logging_module, routing_module, detection_module) {
    loadConfig();
}

SyslogMonitoring::~SyslogMonitoring() {
    // Monitoring durdur
    stop();
}

void SyslogMonitoring::monitor() {
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::INFO,
            "SyslogMonitoring",
            "monitor",
            "Syslog izleme başlatılıyor",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
    }
    
    // İzlenen log dosyalarını oku
    for (const auto& log_file : monitored_log_files_) {
        try {
            auto entries = readLogFile(log_file);
            
            for (const auto& entry : entries) {
                // Log olayını algıla
                auto event = detectLogEvent(entry);
                
                // Tehdit algıla
                detectThreats(event);
                
                // Olayı gönder
                nlohmann::json event_json = event.toJson();
                sendData(event_json, "syslog_events");
            }
        } catch (const std::exception& e) {
            if (logging_module_) {
                logging_module_->log(
                    logging::LogLevel::ERROR,
                    "SyslogMonitoring",
                    "monitor",
                    "Log dosyası okunurken hata: " + std::string(e.what()),
                    __FILE__,
                    __FUNCTION__,
                    std::to_string(__LINE__),
                    std::nullopt
                );
            }
        }
    }
}

void SyslogMonitoring::loadConfig() {
    // Önce temel yapılandırmayı yükle
    MonitoringInterface::loadConfig();
    
    try {
        YAML::Node config = YAML::LoadFile(config_path_);
        auto syslog_monitoring_config = config["monitoring_module"]["syslog_monitoring"];
        
        // İzlenecek log dosyalarını al
        monitored_log_files_.clear();
        if (syslog_monitoring_config["monitored_log_files"]) {
            for (const auto& log_file : syslog_monitoring_config["monitored_log_files"]) {
                monitored_log_files_.push_back(log_file.as<std::string>());
            }
        } else {
            // Varsayılan log dosyaları
#ifdef __APPLE__
            monitored_log_files_.push_back("/var/log/system.log");
            monitored_log_files_.push_back("/var/log/auth.log");
#elif defined(__linux__)
            monitored_log_files_.push_back("/var/log/syslog");
            monitored_log_files_.push_back("/var/log/auth.log");
            monitored_log_files_.push_back("/var/log/secure");
#endif
        }
        
        // İzlenecek tesisleri al
        monitored_facilities_.clear();
        if (syslog_monitoring_config["monitored_facilities"]) {
            for (const auto& facility : syslog_monitoring_config["monitored_facilities"]) {
                monitored_facilities_.push_back(facility.as<std::string>());
            }
        } else {
            // Varsayılan tesisler
            monitored_facilities_.push_back("auth");
            monitored_facilities_.push_back("authpriv");
            monitored_facilities_.push_back("kern");
            monitored_facilities_.push_back("security");
        }
        
        // İzlenecek şiddetleri al
        monitored_severities_.clear();
        if (syslog_monitoring_config["monitored_severities"]) {
            for (const auto& severity : syslog_monitoring_config["monitored_severities"]) {
                monitored_severities_.push_back(severity.as<std::string>());
            }
        } else {
            // Varsayılan şiddetler
            monitored_severities_.push_back("emerg");
            monitored_severities_.push_back("alert");
            monitored_severities_.push_back("crit");
            monitored_severities_.push_back("err");
            monitored_severities_.push_back("warning");
        }
        
        // Hariç tutulacak process'leri al
        excluded_processes_.clear();
        if (syslog_monitoring_config["excluded_processes"]) {
            for (const auto& process : syslog_monitoring_config["excluded_processes"]) {
                excluded_processes_.push_back(process.as<std::string>());
            }
        }
        
        // Olay tespiti için regex'leri al
        event_patterns_.clear();
        
        // Temel regex'leri ekle
        event_patterns_["login_success"] = {std::regex(".*login.*success.*|.*session opened.*|.*authentication success.*|.*accepted password.*"), LogEventType::LOGIN_SUCCESS};
        event_patterns_["login_failure"] = {std::regex(".*login.*fail.*|.*authentication fail.*|.*failed password.*|.*invalid user.*"), LogEventType::LOGIN_FAILURE};
        event_patterns_["logout"] = {std::regex(".*logout.*|.*session closed.*|.*connection closed.*"), LogEventType::LOGOUT};
        
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::INFO,
                "SyslogMonitoring",
                "loadConfig",
                "Syslog izleme yapılandırması yüklendi",
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
    } catch (const std::exception& e) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::ERROR,
                "SyslogMonitoring",
                "loadConfig",
                "Yapılandırma dosyası yüklenemedi: " + std::string(e.what()),
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
    }
}

std::vector<std::string> SyslogMonitoring::getLogFiles() const {
    return monitored_log_files_;
}

std::vector<SyslogEntry> SyslogMonitoring::readLogFile(const std::string& log_file) {
    std::vector<SyslogEntry> entries;
    
    // Dosya var mı kontrol et
    if (!std::filesystem::exists(log_file)) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::ERROR,
                "SyslogMonitoring",
                "readLogFile",
                "Log dosyası bulunamadı: " + log_file,
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
        return entries;
    }
    
    // Dosyayı aç
    std::ifstream file(log_file);
    if (!file.is_open()) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::ERROR,
                "SyslogMonitoring",
                "readLogFile",
                "Log dosyası açılamadı: " + log_file,
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
        return entries;
    }
    
    // Dosya pozisyonunu al
    std::streampos last_pos = 0;
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        auto it = log_positions_.find(log_file);
        if (it != log_positions_.end()) {
            last_pos = it->second;
        }
    }
    
    // Dosyayı son pozisyondan itibaren oku
    file.seekg(last_pos);
    
    std::string line;
    while (std::getline(file, line)) {
        try {
            // Log girişini ayrıştır
            SyslogEntry entry = parseLogEntry(line);
            
            // Process hariç tutulmuş mu kontrol et
            if (std::find(excluded_processes_.begin(), excluded_processes_.end(), entry.process_name) != excluded_processes_.end()) {
                continue;
            }
            
            // Tesis izleniyor mu kontrol et
            if (!monitored_facilities_.empty() && 
                std::find(monitored_facilities_.begin(), monitored_facilities_.end(), entry.facility) == monitored_facilities_.end()) {
                continue;
            }
            
            // Şiddet izleniyor mu kontrol et
            if (!monitored_severities_.empty() && 
                std::find(monitored_severities_.begin(), monitored_severities_.end(), entry.severity) == monitored_severities_.end()) {
                continue;
            }
            
            // Log girişini ekle
            entries.push_back(entry);
        } catch (const std::exception& e) {
            if (logging_module_) {
                logging_module_->log(
                    logging::LogLevel::ERROR,
                    "SyslogMonitoring",
                    "readLogFile",
                    "Log satırı ayrıştırılamadı: " + line + " - " + std::string(e.what()),
                    __FILE__,
                    __FUNCTION__,
                    std::to_string(__LINE__),
                    std::nullopt
                );
            }
        }
    }
    
    // Dosya pozisyonunu güncelle
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        log_positions_[log_file] = file.tellg();
    }
    
    return entries;
}

SyslogEntry SyslogMonitoring::parseLogEntry(const std::string& log_line) {
    SyslogEntry entry;
    
    // Timestamp ayarla
    entry.timestamp = std::chrono::system_clock::now();
    
    // Regex ile log satırını ayrıştır
    std::regex syslog_regex(R"((\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[(\d+)\])?:\s+(.*))");
    std::smatch matches;
    
    if (std::regex_search(log_line, matches, syslog_regex)) {
        // Timestamp
        std::string timestamp_str = matches[1].str();
        
        // Hostname
        entry.hostname = matches[2].str();
        
        // Process name
        entry.process_name = matches[3].str();
        
        // PID
        if (matches[4].matched) {
            entry.pid = std::stoi(matches[4].str());
        } else {
            entry.pid = 0;
        }
        
        // Message
        entry.message = matches[5].str();
    } else {
        // Basit ayrıştırma
        std::istringstream iss(log_line);
        std::string timestamp, hostname, process;
        
        iss >> timestamp >> hostname >> process;
        
        entry.hostname = hostname;
        
        // Process name ve PID ayır
        std::regex process_regex(R"((\S+)(?:\[(\d+)\])?)");
        std::smatch process_matches;
        
        if (std::regex_match(process, process_matches, process_regex)) {
            entry.process_name = process_matches[1].str();
            
            if (process_matches[2].matched) {
                entry.pid = std::stoi(process_matches[2].str());
            } else {
                entry.pid = 0;
            }
        } else {
            entry.process_name = process;
            entry.pid = 0;
        }
        
        // Message
        std::string message;
        std::getline(iss, message);
        
        // Başındaki ": " kaldır
        if (message.size() > 2 && message.substr(0, 2) == ": ") {
            message = message.substr(2);
        }
        
        entry.message = message;
    }
    
    return entry;
}

LogEvent SyslogMonitoring::detectLogEvent(const SyslogEntry& entry) {
    LogEvent event;
    event.log_entry = entry;
    event.event_type = LogEventType::OTHER;
    event.event_description = "Bilinmeyen olay";
    
    // Mesajı kontrol et
    for (const auto& [pattern_name, pattern_info] : event_patterns_) {
        if (std::regex_search(entry.message, pattern_info.first)) {
            event.event_type = pattern_info.second;
            event.event_description = pattern_name;
            
            // Olay detaylarını ekle
            event.event_details["process_name"] = entry.process_name;
            event.event_details["pid"] = entry.pid;
            event.event_details["hostname"] = entry.hostname;
            
            break;
        }
    }
    
    return event;
}

void SyslogMonitoring::detectThreats(const LogEvent& event) {
    if (!detection_module_) {
        return;
    }
    
    // Tehdit algılama için JSON oluştur
    nlohmann::json threat_data = event.toJson();
    threat_data["source"] = "syslog";
    threat_data["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Tehdit algılama modülüne gönder
    detection_module_->detectThreats(threat_data);
}

} // namespace monitoring
} // namespace security_agent 