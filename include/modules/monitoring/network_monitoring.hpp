#pragma once

#include "modules/monitoring/monitoring_interface.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <optional>
#include <fstream>
#include <nlohmann/json.hpp>

namespace security_agent {
namespace monitoring {

/**
 * @brief Ağ protokolü
 */
enum class NetworkProtocol {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    DNS,
    SMTP,
    FTP,
    SSH,
    TELNET,
    OTHER
};

/**
 * @brief Ağ bağlantısı bilgisi
 */
struct NetworkConnection {
    std::string source_ip;
    int source_port;
    std::string destination_ip;
    int destination_port;
    NetworkProtocol protocol;
    std::chrono::system_clock::time_point start_time;
    std::optional<std::chrono::system_clock::time_point> end_time;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    std::string process_name;
    int pid;
    std::string user;
    std::string connection_state;
    
    /**
     * @brief Bağlantı bilgisini JSON formatına dönüştürür
     * 
     * @return JSON formatında bağlantı bilgisi
     */
    nlohmann::json toJson() const;
};

/**
 * @brief Ağ anomalisi türü
 */
enum class NetworkAnomalyType {
    PORT_SCAN,
    DOS_ATTACK,
    BRUTE_FORCE,
    DATA_EXFILTRATION,
    UNUSUAL_PROTOCOL,
    UNUSUAL_PORT,
    UNUSUAL_DESTINATION,
    HIGH_TRAFFIC,
    OTHER
};

/**
 * @brief Ağ anomalisi bilgisi
 */
struct NetworkAnomaly {
    NetworkAnomalyType type;
    std::string description;
    std::chrono::system_clock::time_point detection_time;
    std::vector<NetworkConnection> related_connections;
    nlohmann::json details;
    
    /**
     * @brief Anomali bilgisini JSON formatına dönüştürür
     * 
     * @return JSON formatında anomali bilgisi
     */
    nlohmann::json toJson() const;
};

/**
 * @brief Ağ izleme yapılandırması
 */
struct NetworkMonitoringConfig {
    bool enabled = true;
    std::vector<std::string> interfaces;
    int capture_timeout = 1000; // milisaniye
    int packet_buffer_size = 65536;
    std::vector<std::string> protocols;
    std::vector<int> ports;
    std::vector<std::string> excluded_ips;
    std::string pcap_file;
    uint64_t max_capture_size = 100 * 1024 * 1024; // 100 MB
};

/**
 * @brief Ağ izleme sınıfı
 */
class NetworkMonitoring : public MonitoringInterface {
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
    NetworkMonitoring(
        const std::string& config_path,
        std::shared_ptr<event_management::EventManager> event_manager,
        std::shared_ptr<logging::LoggingModule> logging_module,
        std::shared_ptr<routing::RoutingModule> routing_module,
        std::shared_ptr<detection::DetectionModule> detection_module
    );
    
    /**
     * @brief Yıkıcı fonksiyon
     */
    ~NetworkMonitoring();
    
    /**
     * @brief İzleme işlemini başlatır
     */
    void monitor() override;
    
    /**
     * @brief Yapılandırmayı yükler
     */
    void loadConfig() override;
    
    /**
     * @brief İzlenen arayüzleri döndürür
     * 
     * @return Arayüz listesi
     */
    std::vector<std::string> getInterfaces() const;
    
    /**
     * @brief Paket yakalama işlemini başlatır
     * 
     * @param interface Arayüz adı
     */
    void startCapture(const std::string& interface);
    
    /**
     * @brief Paket yakalama işlemini durdurur
     */
    void stopCapture();
    
    /**
     * @brief Paketi işler
     * 
     * @param packet_data Paket verisi
     */
    void processPacket(const std::vector<uint8_t>& packet_data);
    
    /**
     * @brief Paketin yakalanıp yakalanmayacağını kontrol eder
     * 
     * @param packet_data Paket verisi
     * @return Yakalanacaksa true, değilse false
     */
    bool shouldCapturePacket(const std::vector<uint8_t>& packet_data);
    
    /**
     * @brief Paketi PCAP dosyasına kaydeder
     * 
     * @param packet_data Paket verisi
     */
    void savePacketToPcap(const std::vector<uint8_t>& packet_data);
    
    /**
     * @brief Anomali tespit eder
     * 
     * @param packet_data Paket verisi
     * @return Tespit edilen anomali
     */
    std::optional<NetworkAnomaly> detectAnomaly(const std::vector<uint8_t>& packet_data);
    
    /**
     * @brief Aktif bağlantıları döndürür
     * 
     * @return Bağlantı listesi
     */
    std::vector<NetworkConnection> getActiveConnections() const;
    
    /**
     * @brief Bağlantı geçmişini döndürür
     * 
     * @param limit Maksimum kayıt sayısı
     * @return Bağlantı listesi
     */
    std::vector<NetworkConnection> getConnectionHistory(int limit = 100) const;
    
    /**
     * @brief Anomali geçmişini döndürür
     * 
     * @param limit Maksimum kayıt sayısı
     * @return Anomali listesi
     */
    std::vector<NetworkAnomaly> getAnomalyHistory(int limit = 100) const;
    
private:
    /**
     * @brief Paket başlığını ayrıştırır
     * 
     * @param packet_data Paket verisi
     * @return Bağlantı bilgisi
     */
    NetworkConnection parsePacketHeader(const std::vector<uint8_t>& packet_data);
    
    /**
     * @brief Port taraması tespit eder
     * 
     * @param connection Bağlantı bilgisi
     * @return Tespit edilirse true, değilse false
     */
    bool detectPortScan(const NetworkConnection& connection);
    
    /**
     * @brief DoS saldırısı tespit eder
     * 
     * @param connection Bağlantı bilgisi
     * @return Tespit edilirse true, değilse false
     */
    bool detectDosAttack(const NetworkConnection& connection);
    
    /**
     * @brief Brute force saldırısı tespit eder
     * 
     * @param connection Bağlantı bilgisi
     * @return Tespit edilirse true, değilse false
     */
    bool detectBruteForce(const NetworkConnection& connection);
    
    /**
     * @brief Veri sızıntısı tespit eder
     * 
     * @param connection Bağlantı bilgisi
     * @return Tespit edilirse true, değilse false
     */
    bool detectDataExfiltration(const NetworkConnection& connection);
    
    NetworkMonitoringConfig config_;
    bool capturing_;
    std::string current_interface_;
    uint64_t capture_size_;
    std::vector<NetworkConnection> active_connections_;
    std::vector<NetworkConnection> connection_history_;
    std::vector<NetworkAnomaly> anomaly_history_;
    mutable std::mutex connection_mutex_;
    std::ofstream pcap_file_;
};

} // namespace monitoring
} // namespace security_agent 