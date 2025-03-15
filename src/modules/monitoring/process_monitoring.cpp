#include "modules/monitoring/process_monitoring.hpp"
#include "modules/event_management/event_manager.hpp"
#include "modules/logging/logging_module.hpp"
#include "modules/routing/routing_module.hpp"
#include "modules/detection/detection_module.hpp"
#include <yaml-cpp/yaml.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <thread>
#include <chrono>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#ifdef __APPLE__
#include <sys/sysctl.h>
#include <libproc.h>
#elif defined(__linux__)
#include <dirent.h>
#include <sys/stat.h>
#endif

namespace security_agent {
namespace monitoring {

// ProcessInfo sınıfı implementasyonu
nlohmann::json ProcessInfo::toJson() const {
    nlohmann::json json;
    json["pid"] = pid;
    json["name"] = name;
    json["path"] = path;
    json["command_line"] = command_line;
    json["user"] = user;
    json["start_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        start_time.time_since_epoch()).count();
    json["cpu_usage"] = cpu_usage;
    json["memory_usage"] = memory_usage;
    json["virtual_memory"] = virtual_memory;
    json["resident_memory"] = resident_memory;
    json["threads"] = threads;
    json["parent_pid"] = parent_pid;
    json["status"] = status;
    json["priority"] = priority;
    json["nice"] = nice;
    
    nlohmann::json network_connections_json = nlohmann::json::array();
    for (const auto& connection : network_connections) {
        nlohmann::json conn_json;
        conn_json["local_address"] = connection.local_address;
        conn_json["local_port"] = connection.local_port;
        conn_json["remote_address"] = connection.remote_address;
        conn_json["remote_port"] = connection.remote_port;
        conn_json["state"] = connection.state;
        conn_json["protocol"] = connection.protocol;
        network_connections_json.push_back(conn_json);
    }
    json["network_connections"] = network_connections_json;
    
    nlohmann::json open_files_json = nlohmann::json::array();
    for (const auto& file : open_files) {
        open_files_json.push_back(file);
    }
    json["open_files"] = open_files_json;
    
    return json;
}

// ProcessAnomaly sınıfı implementasyonu
nlohmann::json ProcessAnomaly::toJson() const {
    nlohmann::json json;
    
    // Anomali tipini string'e dönüştür
    std::string type_str = typeToString(type);
    json["type"] = type_str;
    
    json["description"] = description;
    json["detection_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        detection_time.time_since_epoch()).count();
    json["process"] = process.toJson();
    json["details"] = details;
    
    return json;
}

std::string ProcessAnomaly::typeToString(ProcessAnomalyType type) const {
    switch (type) {
        case ProcessAnomalyType::HIGH_CPU_USAGE: return "HIGH_CPU_USAGE";
        case ProcessAnomalyType::HIGH_MEMORY_USAGE: return "HIGH_MEMORY_USAGE";
        case ProcessAnomalyType::HIGH_DISK_USAGE: return "HIGH_DISK_USAGE";
        case ProcessAnomalyType::HIGH_NETWORK_USAGE: return "HIGH_NETWORK_USAGE";
        case ProcessAnomalyType::SUSPICIOUS_PROCESS: return "SUSPICIOUS_PROCESS";
        case ProcessAnomalyType::SUSPICIOUS_EXECUTABLE: return "SUSPICIOUS_EXECUTABLE";
        case ProcessAnomalyType::UNUSUAL_PARENT_CHILD: return "UNUSUAL_PARENT_CHILD";
        default: return "UNKNOWN";
    }
}

// ProcessMonitoring sınıfı implementasyonu
ProcessMonitoring::ProcessMonitoring(
    const std::string& config_path,
    std::shared_ptr<event_management::EventManager> event_manager,
    std::shared_ptr<logging::LoggingModule> logging_module,
    std::shared_ptr<routing::RoutingModule> routing_module,
    std::shared_ptr<detection::DetectionModule> detection_module
) : MonitoringInterface(config_path, event_manager, logging_module, routing_module, detection_module),
    monitoring_(false) {
    
    loadConfig();
    loadSuspiciousProcesses();
}

ProcessMonitoring::~ProcessMonitoring() {
    stopMonitoring();
}

void ProcessMonitoring::monitor() {
    if (!config_.enabled) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::INFO,
                "ProcessMonitoring",
                "monitor",
                "Süreç izleme devre dışı",
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
        return;
    }
    
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::INFO,
            "ProcessMonitoring",
            "monitor",
            "Süreç izleme başlatılıyor",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
    }
    
    startMonitoring();
}

void ProcessMonitoring::loadConfig() {
    try {
        YAML::Node config = YAML::LoadFile(config_path_);
        auto process_monitoring_config = config["monitoring_module"]["process_monitoring"];
        
        // Temel yapılandırma
        config_.enabled = process_monitoring_config["enabled"] ? 
            process_monitoring_config["enabled"].as<bool>() : true;
        
        // İzleme aralığı
        int scan_interval = process_monitoring_config["scan_interval"] ? 
            process_monitoring_config["scan_interval"].as<int>() : 5000;
        
        // CPU kullanım eşiği
        config_.cpu_threshold = process_monitoring_config["cpu_threshold"] ? 
            process_monitoring_config["cpu_threshold"].as<double>() : 80.0;
        
        // Bellek kullanım eşiği
        config_.memory_threshold = process_monitoring_config["memory_threshold"] ? 
            process_monitoring_config["memory_threshold"].as<double>() : 80.0;
        
        // Disk kullanım eşiği
        config_.disk_threshold = process_monitoring_config["disk_threshold"] ? 
            process_monitoring_config["disk_threshold"].as<double>() : 80.0;
        
        // Ağ kullanım eşiği
        config_.network_threshold = process_monitoring_config["network_threshold"] ? 
            process_monitoring_config["network_threshold"].as<double>() : 80.0;
        
        // İzlenecek süreçler
        std::vector<std::string> monitored_processes;
        if (process_monitoring_config["monitored_processes"]) {
            for (const auto& process : process_monitoring_config["monitored_processes"]) {
                monitored_processes.push_back(process.as<std::string>());
            }
        }
        
        // Hariç tutulan süreçler
        config_.excluded_processes.clear();
        if (process_monitoring_config["excluded_processes"]) {
            for (const auto& process : process_monitoring_config["excluded_processes"]) {
                config_.excluded_processes.push_back(process.as<std::string>());
            }
        }
        
        // Şüpheli süreç dosyası
        std::string suspicious_processes_file = process_monitoring_config["suspicious_processes_file"] ? 
            process_monitoring_config["suspicious_processes_file"].as<std::string>() : 
            "config/suspicious_processes.json";
        
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::INFO,
                "ProcessMonitoring",
                "loadConfig",
                "Süreç izleme yapılandırması yüklendi",
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
                "ProcessMonitoring",
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

void ProcessMonitoring::loadSuspiciousProcesses() {
    try {
        std::string suspicious_processes_file = "config/suspicious_processes.json";
        std::ifstream file(suspicious_processes_file);
        if (!file.is_open()) {
            if (logging_module_) {
                logging_module_->log(
                    logging::LogLevel::WARNING,
                    "ProcessMonitoring",
                    "loadSuspiciousProcesses",
                    "Şüpheli süreç dosyası açılamadı: " + suspicious_processes_file,
                    __FILE__,
                    __FUNCTION__,
                    std::to_string(__LINE__),
                    std::nullopt
                );
            }
            return;
        }
        
        nlohmann::json json;
        file >> json;
        
        suspicious_processes_.clear();
        for (const auto& item : json) {
            SuspiciousProcess process;
            process.name = item["name"].get<std::string>();
            process.hash = item["hash"].get<std::string>();
            process.description = item["description"].get<std::string>();
            suspicious_processes_.push_back(process);
        }
        
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::INFO,
                "ProcessMonitoring",
                "loadSuspiciousProcesses",
                "Şüpheli süreçler yüklendi: " + std::to_string(suspicious_processes_.size()) + " süreç",
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
                "ProcessMonitoring",
                "loadSuspiciousProcesses",
                "Şüpheli süreç dosyası yüklenemedi: " + std::string(e.what()),
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
    }
}

void ProcessMonitoring::startMonitoring() {
    if (monitoring_) {
        return;
    }
    
    monitoring_ = true;
    
    // İzleme iş parçacığını başlat
    monitoring_thread_ = std::thread([this]() {
        while (monitoring_) {
            // Tüm süreçleri al
            auto processes = getAllProcesses();
            
            // Süreçleri işle
            for (const auto& process : processes) {
                processProcess(process);
            }
            
            // Anomalileri tespit et
            detectAnomalies(processes);
            
            // İzleme aralığı kadar bekle
            std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        }
    });
}

void ProcessMonitoring::stopMonitoring() {
    if (!monitoring_) {
        return;
    }
    
    monitoring_ = false;
    
    if (monitoring_thread_.joinable()) {
        monitoring_thread_.join();
    }
    
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::INFO,
            "ProcessMonitoring",
            "stopMonitoring",
            "Süreç izleme durduruldu",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
    }
}

std::vector<ProcessInfo> ProcessMonitoring::getAllProcesses() {
    std::vector<ProcessInfo> processes;
    
    // Burada gerçek bir süreç listesi alınacak
    // Şimdilik örnek süreçler oluşturuyoruz
    
    // Örnek süreç 1
    ProcessInfo process1;
    process1.pid = 1234;
    process1.name = "example1";
    process1.path = "/usr/bin/example1";
    process1.command_line = "/usr/bin/example1 --arg1 --arg2";
    process1.user = "user";
    process1.start_time = std::chrono::system_clock::now() - std::chrono::hours(1);
    process1.cpu_usage = 5.0;
    process1.memory_usage = 10.0;
    process1.virtual_memory = 100 * 1024 * 1024;
    process1.resident_memory = 50 * 1024 * 1024;
    process1.threads = 4;
    process1.parent_pid = 1;
    process1.status = "running";
    process1.priority = 0;
    process1.nice = 0;
    
    // Ağ bağlantıları
    ProcessNetworkConnection conn1;
    conn1.local_address = "127.0.0.1";
    conn1.local_port = 12345;
    conn1.remote_address = "192.168.1.1";
    conn1.remote_port = 80;
    conn1.state = "ESTABLISHED";
    conn1.protocol = "TCP";
    process1.network_connections.push_back(conn1);
    
    // Açık dosyalar
    process1.open_files.push_back("/var/log/example.log");
    process1.open_files.push_back("/etc/example.conf");
    
    processes.push_back(process1);
    
    // Örnek süreç 2
    ProcessInfo process2;
    process2.pid = 5678;
    process2.name = "example2";
    process2.path = "/usr/bin/example2";
    process2.command_line = "/usr/bin/example2 --arg1 --arg2";
    process2.user = "root";
    process2.start_time = std::chrono::system_clock::now() - std::chrono::hours(2);
    process2.cpu_usage = 90.0;
    process2.memory_usage = 85.0;
    process2.virtual_memory = 500 * 1024 * 1024;
    process2.resident_memory = 250 * 1024 * 1024;
    process2.threads = 8;
    process2.parent_pid = 1;
    process2.status = "running";
    process2.priority = 0;
    process2.nice = 0;
    
    processes.push_back(process2);
    
    return processes;
}

void ProcessMonitoring::processProcess(const ProcessInfo& process) {
    // Süreç izleme listesinde mi kontrol et
    std::vector<std::string> monitored_processes;
    if (!monitored_processes.empty()) {
        bool found = false;
        for (const auto& monitored_process : monitored_processes) {
            if (process.name == monitored_process) {
                found = true;
                break;
            }
        }
        
        if (!found) {
            return;
        }
    }
    
    // Hariç tutulan süreçler listesinde mi kontrol et
    for (const auto& excluded_process : config_.excluded_processes) {
        if (process.name == excluded_process) {
            return;
        }
    }
    
    // Süreç bilgilerini kaydet
    {
        std::lock_guard<std::mutex> lock(process_mutex_);
        
        // Aktif süreçleri güncelle
        active_processes_[process.pid] = process;
        
        // Süreç geçmişini güncelle
        process_history_.push_back(process);
        
        // Geçmiş boyutunu sınırla
        if (process_history_.size() > 1000) {
            process_history_.erase(process_history_.begin());
        }
    }
}

void ProcessMonitoring::detectAnomalies(const std::vector<ProcessInfo>& processes) {
    for (const auto& process : processes) {
        // Yüksek CPU kullanımı
        if (process.cpu_usage > config_.cpu_threshold) {
            ProcessAnomaly anomaly;
            anomaly.type = ProcessAnomalyType::HIGH_CPU_USAGE;
            anomaly.description = "Yüksek CPU kullanımı tespit edildi";
            anomaly.detection_time = std::chrono::system_clock::now();
            anomaly.process = process;
            
            nlohmann::json details;
            details["cpu_usage"] = process.cpu_usage;
            details["threshold"] = config_.cpu_threshold;
            anomaly.details = details;
            
            reportAnomaly(anomaly);
        }
        
        // Yüksek bellek kullanımı
        if (process.memory_usage > config_.memory_threshold) {
            ProcessAnomaly anomaly;
            anomaly.type = ProcessAnomalyType::HIGH_MEMORY_USAGE;
            anomaly.description = "Yüksek bellek kullanımı tespit edildi";
            anomaly.detection_time = std::chrono::system_clock::now();
            anomaly.process = process;
            
            nlohmann::json details;
            details["memory_usage"] = process.memory_usage;
            details["threshold"] = config_.memory_threshold;
            anomaly.details = details;
            
            reportAnomaly(anomaly);
        }
        
        // Şüpheli süreç
        for (const auto& suspicious_process : suspicious_processes_) {
            if (process.name == suspicious_process.name) {
                ProcessAnomaly anomaly;
                anomaly.type = ProcessAnomalyType::SUSPICIOUS_BEHAVIOR;
                anomaly.description = "Şüpheli süreç tespit edildi: " + suspicious_process.description;
                anomaly.detection_time = std::chrono::system_clock::now();
                anomaly.process = process;
                
                nlohmann::json details;
                details["name"] = suspicious_process.name;
                details["hash"] = suspicious_process.hash;
                details["description"] = suspicious_process.description;
                anomaly.details = details;
                
                reportAnomaly(anomaly);
                break;
            }
        }
    }
}

void ProcessMonitoring::reportAnomaly(const ProcessAnomaly& anomaly) {
    // Anomaliyi kaydet
    {
        std::lock_guard<std::mutex> lock(process_mutex_);
        anomaly_history_.push_back(anomaly);
        
        // Geçmiş boyutunu sınırla
        if (anomaly_history_.size() > 1000) {
            anomaly_history_.erase(anomaly_history_.begin());
        }
    }
    
    // Anomaliyi detection modülüne gönder
    if (detection_module_) {
        detection_module_->detectThreats(anomaly.toJson());
    }
    
    // Anomaliyi log'a yaz
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::WARNING,
            "ProcessMonitoring",
            "reportAnomaly",
            "Süreç anomalisi tespit edildi: " + anomaly.description,
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            anomaly.toJson()
        );
    }
}

std::vector<ProcessInfo> ProcessMonitoring::getActiveProcesses() const {
    std::lock_guard<std::mutex> lock(process_mutex_);
    
    std::vector<ProcessInfo> processes;
    for (const auto& pair : active_processes_) {
        processes.push_back(pair.second);
    }
    
    return processes;
}

std::vector<ProcessInfo> ProcessMonitoring::getProcessHistory(int limit) const {
    std::lock_guard<std::mutex> lock(process_mutex_);
    
    if (limit <= 0 || limit >= static_cast<int>(process_history_.size())) {
        return process_history_;
    }
    
    return std::vector<ProcessInfo>(
        process_history_.end() - limit,
        process_history_.end()
    );
}

std::vector<ProcessAnomaly> ProcessMonitoring::getAnomalyHistory(int limit) const {
    std::lock_guard<std::mutex> lock(process_mutex_);
    
    if (limit <= 0 || limit >= static_cast<int>(anomaly_history_.size())) {
        return anomaly_history_;
    }
    
    return std::vector<ProcessAnomaly>(
        anomaly_history_.end() - limit,
        anomaly_history_.end()
    );
}

} // namespace monitoring
} // namespace security_agent 