#pragma once

#include "modules/monitoring/monitoring_interface.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <optional>
#include <thread>
#include <nlohmann/json.hpp>

namespace security_agent {
namespace monitoring {

/**
 * @brief Süreç ağ bağlantısı bilgisi
 */
struct ProcessNetworkConnection {
    std::string local_address;
    int local_port;
    std::string remote_address;
    int remote_port;
    std::string state;
    std::string protocol;
};

/**
 * @brief Süreç bilgisi
 */
struct ProcessInfo {
    int pid;
    std::string name;
    std::string path;
    std::string command_line;
    std::string user;
    std::chrono::system_clock::time_point start_time;
    double cpu_usage;
    double memory_usage;
    uint64_t virtual_memory;
    uint64_t resident_memory;
    int threads;
    int parent_pid;
    std::string status;
    int priority;
    int nice;
    std::vector<ProcessNetworkConnection> network_connections;
    std::vector<std::string> open_files;
    
    /**
     * @brief Süreç bilgisini JSON formatına dönüştürür
     * 
     * @return JSON formatında süreç bilgisi
     */
    nlohmann::json toJson() const;
};

/**
 * @brief Şüpheli süreç bilgisi
 */
struct SuspiciousProcess {
    std::string name;
    std::string hash;
    std::string description;
};

/**
 * @brief Süreç anomalisi türü
 */
enum class ProcessAnomalyType {
    HIGH_CPU_USAGE,
    HIGH_MEMORY_USAGE,
    HIGH_NETWORK_USAGE,
    HIGH_DISK_USAGE,
    SUSPICIOUS_PROCESS,
    SUSPICIOUS_EXECUTABLE,
    SUSPICIOUS_BEHAVIOR,
    PRIVILEGE_ESCALATION,
    UNUSUAL_PARENT_CHILD,
    OTHER
};

/**
 * @brief Süreç anomalisi bilgisi
 */
struct ProcessAnomaly {
    ProcessAnomalyType type;
    std::string description;
    std::chrono::system_clock::time_point detection_time;
    ProcessInfo process;
    nlohmann::json details;
    
    /**
     * @brief Anomali bilgisini JSON formatına dönüştürür
     * 
     * @return JSON formatında anomali bilgisi
     */
    nlohmann::json toJson() const;
    
    /**
     * @brief Anomali tipini string'e dönüştürür
     * 
     * @param type Anomali tipi
     * @return String formatında anomali tipi
     */
    std::string typeToString(ProcessAnomalyType type) const;
};

/**
 * @brief Süreç izleme yapılandırması
 */
struct ProcessMonitoringConfig {
    bool enabled = true;
    int scan_interval = 60; // saniye
    int process_history_size = 1000;
    std::vector<SuspiciousProcess> suspicious_processes;
    std::vector<std::string> excluded_processes;
    double cpu_threshold = 90.0;
    double memory_threshold = 90.0;
    uint64_t network_threshold = 10 * 1024 * 1024; // 10 MB/s
    uint64_t disk_threshold = 50 * 1024 * 1024; // 50 MB/s
};

/**
 * @brief Süreç izleme sınıfı
 */
class ProcessMonitoring : public MonitoringInterface {
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
    ProcessMonitoring(
        const std::string& config_path,
        std::shared_ptr<event_management::EventManager> event_manager,
        std::shared_ptr<logging::LoggingModule> logging_module,
        std::shared_ptr<routing::RoutingModule> routing_module,
        std::shared_ptr<detection::DetectionModule> detection_module
    );
    
    /**
     * @brief Yıkıcı fonksiyon
     */
    ~ProcessMonitoring();
    
    /**
     * @brief İzleme işlemini başlatır
     */
    void monitor() override;
    
    /**
     * @brief Yapılandırmayı yükler
     */
    void loadConfig() override;
    
    /**
     * @brief Çalışan süreçleri döndürür
     * 
     * @return Süreç listesi
     */
    std::vector<ProcessInfo> getRunningProcesses();
    
    /**
     * @brief Süreç bilgisini JSON formatına dönüştürür
     * 
     * @param process Süreç bilgisi
     * @return JSON formatında süreç bilgisi
     */
    nlohmann::json processInfoToJson(const ProcessInfo& process);
    
    /**
     * @brief Süreç hash değerini hesaplar
     * 
     * @param process Süreç bilgisi
     * @return Hash değeri
     */
    std::string calculateProcessHash(const ProcessInfo& process);
    
    /**
     * @brief Sürecin şüpheli olup olmadığını kontrol eder
     * 
     * @param process Süreç bilgisi
     * @return Şüpheli ise true, değilse false
     */
    bool isSuspiciousProcess(const ProcessInfo& process);
    
    /**
     * @brief Sürecin anormal kaynak kullanımı olup olmadığını kontrol eder
     * 
     * @param process Süreç bilgisi
     * @return Anormal ise true, değilse false
     */
    bool hasAnomalousResourceUsage(const ProcessInfo& process);
    
    /**
     * @brief Şüpheli süreçleri döndürür
     * 
     * @return Şüpheli süreç listesi
     */
    const std::vector<SuspiciousProcess>& getSuspiciousProcesses() const;
    
    /**
     * @brief Süreç geçmişini döndürür
     * 
     * @param limit Maksimum kayıt sayısı
     * @return Süreç listesi
     */
    std::vector<ProcessInfo> getProcessHistory(int limit = 100) const;
    
    /**
     * @brief Anomali geçmişini döndürür
     * 
     * @param limit Maksimum kayıt sayısı
     * @return Anomali listesi
     */
    std::vector<ProcessAnomaly> getAnomalyHistory(int limit = 100) const;
    
private:
    /**
     * @brief Süreç bilgisini alır
     * 
     * @param pid Süreç ID
     * @return Süreç bilgisi
     */
    ProcessInfo getProcessInfo(int pid);
    
    /**
     * @brief Süreç anomalisi tespit eder
     * 
     * @param process Süreç bilgisi
     * @return Tespit edilen anomali
     */
    std::optional<ProcessAnomaly> detectProcessAnomaly(const ProcessInfo& process);
    
    /**
     * @brief Süreç değişikliği tespit eder
     * 
     * @param old_process Eski süreç bilgisi
     * @param new_process Yeni süreç bilgisi
     * @return Değişiklik varsa true, yoksa false
     */
    bool detectProcessChange(const ProcessInfo& old_process, const ProcessInfo& new_process);
    
    /**
     * @brief Anomali olayı oluşturur
     * 
     * @param anomaly Anomali bilgisi
     */
    void raiseAnomalyEvent(const ProcessAnomaly& anomaly);
    
    void loadSuspiciousProcesses();
    void startMonitoring();
    void stopMonitoring();
    std::vector<ProcessInfo> getAllProcesses();
    void processProcess(const ProcessInfo& process);
    void detectAnomalies(const std::vector<ProcessInfo>& processes);
    void reportAnomaly(const ProcessAnomaly& anomaly);
    std::vector<ProcessInfo> getActiveProcesses() const;
    
    ProcessMonitoringConfig config_;
    mutable std::mutex process_mutex_;
    std::unordered_map<int, ProcessInfo> active_processes_;
    std::vector<ProcessInfo> process_history_;
    std::vector<ProcessAnomaly> anomaly_history_;
    std::vector<SuspiciousProcess> suspicious_processes_;
    bool monitoring_;
    std::thread monitoring_thread_;
};

} // namespace monitoring
} // namespace security_agent 