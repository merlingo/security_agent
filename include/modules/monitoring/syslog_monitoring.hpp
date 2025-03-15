#pragma once

#include "modules/monitoring/monitoring_interface.hpp"
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <regex>
#include <chrono>

namespace security_agent {
namespace monitoring {

/**
 * @brief Sistem log girişi yapısı
 */
struct SyslogEntry {
    std::chrono::system_clock::time_point timestamp;
    std::string facility;
    std::string severity;
    std::string hostname;
    std::string process_name;
    int pid;
    std::string message;
    std::string source_file;
    std::string user;
    
    /**
     * @brief Log girişini JSON formatına dönüştürür
     * 
     * @return JSON formatında log girişi
     */
    nlohmann::json toJson() const;
    
    /**
     * @brief Log girişi için benzersiz hash değeri hesaplar
     * 
     * @return Hash değeri
     */
    std::string calculateHash() const;
};

/**
 * @brief Log olay türleri
 */
enum class LogEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT,
    ACCOUNT_CHANGE,
    PRIVILEGE_ESCALATION,
    PROCESS_START,
    PROCESS_STOP,
    SERVICE_START,
    SERVICE_STOP,
    SYSTEM_BOOT,
    SYSTEM_SHUTDOWN,
    FIREWALL_CHANGE,
    NETWORK_CHANGE,
    FILE_ACCESS,
    FILE_CHANGE,
    CRON_JOB,
    SECURITY_ALERT,
    OTHER
};

/**
 * @brief Log olayı yapısı
 */
struct LogEvent {
    SyslogEntry log_entry;
    LogEventType event_type;
    std::string event_description;
    nlohmann::json event_details;
    
    /**
     * @brief Log olayını JSON formatına dönüştürür
     * 
     * @return JSON formatında log olayı
     */
    nlohmann::json toJson() const;
};

/**
 * @brief Sistem log izleme sınıfı
 */
class SyslogMonitoring : public MonitoringInterface {
public:
    /**
     * @brief Yapıcı fonksiyon
     * 
     * @param config_path Yapılandırma dosyasının yolu
     * @param event_manager Olay yöneticisi
     * @param logging_module Günlük modülü
     * @param routing_module Yönlendirme modülü
     * @param detection_module Tehdit algılama modülü
     */
    SyslogMonitoring(
        const std::string& config_path,
        std::shared_ptr<event_management::EventManager> event_manager,
        std::shared_ptr<logging::LoggingModule> logging_module,
        std::shared_ptr<routing::RoutingModule> routing_module,
        std::shared_ptr<detection::DetectionModule> detection_module
    );
    
    /**
     * @brief Yıkıcı fonksiyon
     */
    ~SyslogMonitoring();
    
    /**
     * @brief İzleme işlemini başlatır
     */
    void monitor() override;
    
    /**
     * @brief Yapılandırmayı yükler
     */
    void loadConfig() override;
    
    /**
     * @brief İzlenen log dosyalarını döndürür
     * 
     * @return Log dosyaları listesi
     */
    std::vector<std::string> getLogFiles() const;
    
    /**
     * @brief Log dosyasını okur
     * 
     * @param log_file Log dosyası yolu
     * @return Okunan log girişleri
     */
    std::vector<SyslogEntry> readLogFile(const std::string& log_file);
    
    /**
     * @brief Log satırını ayrıştırır
     * 
     * @param log_line Log satırı
     * @return Ayrıştırılmış log girişi
     */
    SyslogEntry parseLogEntry(const std::string& log_line);
    
    /**
     * @brief Log girişinden olay algılar
     * 
     * @param entry Log girişi
     * @return Algılanan log olayı
     */
    LogEvent detectLogEvent(const SyslogEntry& entry);
    
    /**
     * @brief Log olayından tehdit algılar
     * 
     * @param event Log olayı
     */
    void detectThreats(const LogEvent& event);
    
private:
    // Log dosyası pozisyonları
    std::unordered_map<std::string, std::streampos> log_positions_;
    
    // Mutex
    std::mutex log_mutex_;
    
    // İzlenen log dosyaları
    std::vector<std::string> monitored_log_files_;
    
    // İzlenen tesisler
    std::vector<std::string> monitored_facilities_;
    
    // İzlenen şiddetler
    std::vector<std::string> monitored_severities_;
    
    // Hariç tutulan process'ler
    std::vector<std::string> excluded_processes_;
    
    // Olay tespiti için regex'ler
    std::unordered_map<std::string, std::pair<std::regex, LogEventType>> event_patterns_;
};

} // namespace monitoring
} // namespace security_agent 