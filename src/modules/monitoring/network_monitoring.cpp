#include "modules/monitoring/network_monitoring.hpp"
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

namespace security_agent {
namespace monitoring {

// NetworkConnection sınıfı implementasyonu
nlohmann::json NetworkConnection::toJson() const {
    nlohmann::json json;
    json["source_ip"] = source_ip;
    json["source_port"] = source_port;
    json["destination_ip"] = destination_ip;
    json["destination_port"] = destination_port;
    
    // Protocol enum'unu string'e dönüştür
    std::string protocol_str;
    switch (protocol) {
        case NetworkProtocol::TCP: protocol_str = "TCP"; break;
        case NetworkProtocol::UDP: protocol_str = "UDP"; break;
        case NetworkProtocol::ICMP: protocol_str = "ICMP"; break;
        case NetworkProtocol::HTTP: protocol_str = "HTTP"; break;
        case NetworkProtocol::HTTPS: protocol_str = "HTTPS"; break;
        case NetworkProtocol::DNS: protocol_str = "DNS"; break;
        case NetworkProtocol::SMTP: protocol_str = "SMTP"; break;
        case NetworkProtocol::FTP: protocol_str = "FTP"; break;
        case NetworkProtocol::SSH: protocol_str = "SSH"; break;
        case NetworkProtocol::TELNET: protocol_str = "TELNET"; break;
        case NetworkProtocol::OTHER: protocol_str = "OTHER"; break;
    }
    json["protocol"] = protocol_str;
    
    json["start_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        start_time.time_since_epoch()).count();
    
    if (end_time) {
        json["end_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time->time_since_epoch()).count();
    }
    
    json["bytes_sent"] = bytes_sent;
    json["bytes_received"] = bytes_received;
    json["process_name"] = process_name;
    json["pid"] = pid;
    json["user"] = user;
    json["connection_state"] = connection_state;
    
    return json;
}

// NetworkAnomaly sınıfı implementasyonu
nlohmann::json NetworkAnomaly::toJson() const {
    nlohmann::json json;
    
    // Anomali tipini string'e dönüştür
    std::string type_str;
    switch (type) {
        case NetworkAnomalyType::PORT_SCAN: type_str = "PORT_SCAN"; break;
        case NetworkAnomalyType::DOS_ATTACK: type_str = "DOS_ATTACK"; break;
        case NetworkAnomalyType::BRUTE_FORCE: type_str = "BRUTE_FORCE"; break;
        case NetworkAnomalyType::DATA_EXFILTRATION: type_str = "DATA_EXFILTRATION"; break;
        case NetworkAnomalyType::UNUSUAL_PROTOCOL: type_str = "UNUSUAL_PROTOCOL"; break;
        case NetworkAnomalyType::UNUSUAL_PORT: type_str = "UNUSUAL_PORT"; break;
        case NetworkAnomalyType::UNUSUAL_DESTINATION: type_str = "UNUSUAL_DESTINATION"; break;
        case NetworkAnomalyType::HIGH_TRAFFIC: type_str = "HIGH_TRAFFIC"; break;
        case NetworkAnomalyType::OTHER: type_str = "OTHER"; break;
    }
    json["type"] = type_str;
    
    json["description"] = description;
    json["detection_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        detection_time.time_since_epoch()).count();
    
    nlohmann::json connections_json = nlohmann::json::array();
    for (const auto& connection : related_connections) {
        connections_json.push_back(connection.toJson());
    }
    json["related_connections"] = connections_json;
    json["details"] = details;
    
    return json;
}

// NetworkMonitoring sınıfı implementasyonu
NetworkMonitoring::NetworkMonitoring(
    const std::string& config_path,
    std::shared_ptr<event_management::EventManager> event_manager,
    std::shared_ptr<logging::LoggingModule> logging_module,
    std::shared_ptr<routing::RoutingModule> routing_module,
    std::shared_ptr<detection::DetectionModule> detection_module
) : MonitoringInterface(config_path, event_manager, logging_module, routing_module, detection_module),
    capturing_(false),
    capture_size_(0) {
    
    loadConfig();
}

NetworkMonitoring::~NetworkMonitoring() {
    stopCapture();
}

void NetworkMonitoring::monitor() {
    if (!config_.enabled) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::INFO,
                "NetworkMonitoring",
                "monitor",
                "Ağ izleme devre dışı",
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
            "NetworkMonitoring",
            "monitor",
            "Ağ izleme başlatılıyor",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
    }
    
    // Tüm arayüzleri izle
    for (const auto& interface : config_.interfaces) {
        startCapture(interface);
    }
}

void NetworkMonitoring::loadConfig() {
    try {
        YAML::Node config = YAML::LoadFile(config_path_);
        auto network_monitoring_config = config["monitoring_module"]["network_monitoring"];
        
        // Temel yapılandırma
        config_.enabled = network_monitoring_config["enabled"] ? 
            network_monitoring_config["enabled"].as<bool>() : true;
        
        // Arayüzler
        config_.interfaces.clear();
        if (network_monitoring_config["interfaces"]) {
            for (const auto& interface : network_monitoring_config["interfaces"]) {
                config_.interfaces.push_back(interface.as<std::string>());
            }
        } else {
            // Varsayılan arayüzler
            config_.interfaces.push_back("eth0");
            config_.interfaces.push_back("lo");
        }
        
        // Yakalama zaman aşımı
        config_.capture_timeout = network_monitoring_config["capture_timeout"] ? 
            network_monitoring_config["capture_timeout"].as<int>() : 1000;
        
        // Paket arabellek boyutu
        config_.packet_buffer_size = network_monitoring_config["packet_buffer_size"] ? 
            network_monitoring_config["packet_buffer_size"].as<int>() : 65536;
        
        // Protokoller
        config_.protocols.clear();
        if (network_monitoring_config["protocols"]) {
            for (const auto& protocol : network_monitoring_config["protocols"]) {
                config_.protocols.push_back(protocol.as<std::string>());
            }
        } else {
            // Varsayılan protokoller
            config_.protocols.push_back("tcp");
            config_.protocols.push_back("udp");
            config_.protocols.push_back("icmp");
        }
        
        // Portlar
        config_.ports.clear();
        if (network_monitoring_config["ports"]) {
            for (const auto& port : network_monitoring_config["ports"]) {
                config_.ports.push_back(port.as<int>());
            }
        }
        
        // Hariç tutulan IP'ler
        config_.excluded_ips.clear();
        if (network_monitoring_config["excluded_ips"]) {
            for (const auto& ip : network_monitoring_config["excluded_ips"]) {
                config_.excluded_ips.push_back(ip.as<std::string>());
            }
        }
        
        // PCAP dosyası
        config_.pcap_file = network_monitoring_config["pcap_file"] ? 
            network_monitoring_config["pcap_file"].as<std::string>() : "";
        
        // Maksimum yakalama boyutu
        config_.max_capture_size = network_monitoring_config["max_capture_size"] ? 
            network_monitoring_config["max_capture_size"].as<uint64_t>() : 100 * 1024 * 1024;
        
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::INFO,
                "NetworkMonitoring",
                "loadConfig",
                "Ağ izleme yapılandırması yüklendi",
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
                "NetworkMonitoring",
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

std::vector<std::string> NetworkMonitoring::getInterfaces() const {
    return config_.interfaces;
}

void NetworkMonitoring::startCapture(const std::string& interface) {
    if (capturing_) {
        stopCapture();
    }
    
    capturing_ = true;
    current_interface_ = interface;
    
    if (!config_.pcap_file.empty()) {
        // PCAP dosyasını aç
        std::filesystem::path pcap_path(config_.pcap_file);
        std::filesystem::create_directories(pcap_path.parent_path());
        
        // Burada gerçek bir PCAP dosyası açma işlemi yapılacak
        // Şimdilik sadece log yazıyoruz
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::INFO,
                "NetworkMonitoring",
                "startCapture",
                "PCAP dosyası açıldı: " + config_.pcap_file,
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
    }
    
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::INFO,
            "NetworkMonitoring",
            "startCapture",
            "Ağ yakalama başlatıldı: " + interface,
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
    }
    
    // Burada gerçek bir paket yakalama işlemi başlatılacak
    // Şimdilik sadece log yazıyoruz
}

void NetworkMonitoring::stopCapture() {
    if (!capturing_) {
        return;
    }
    
    capturing_ = false;
    
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::INFO,
            "NetworkMonitoring",
            "stopCapture",
            "Ağ yakalama durduruldu: " + current_interface_,
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
    }
    
    // Burada gerçek bir paket yakalama işlemi durdurulacak
    // Şimdilik sadece log yazıyoruz
}

void NetworkMonitoring::processPacket(const std::vector<uint8_t>& packet_data) {
    if (!shouldCapturePacket(packet_data)) {
        return;
    }
    
    // Paket başlığını ayrıştır
    auto connection = parsePacketHeader(packet_data);
    
    // Bağlantıyı kaydet
    {
        std::lock_guard<std::mutex> lock(connection_mutex_);
        active_connections_.push_back(connection);
        connection_history_.push_back(connection);
        
        // Geçmiş boyutunu sınırla
        if (connection_history_.size() > 1000) {
            connection_history_.erase(connection_history_.begin());
        }
    }
    
    // Anomali tespit et
    auto anomaly = detectAnomaly(packet_data);
    if (anomaly) {
        // Anomaliyi kaydet
        {
            std::lock_guard<std::mutex> lock(connection_mutex_);
            anomaly_history_.push_back(*anomaly);
            
            // Geçmiş boyutunu sınırla
            if (anomaly_history_.size() > 1000) {
                anomaly_history_.erase(anomaly_history_.begin());
            }
        }
        
        // Anomaliyi detection modülüne gönder
        if (detection_module_) {
            detection_module_->detectThreats(anomaly->toJson());
        }
        
        // Anomaliyi log'a yaz
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::WARNING,
                "NetworkMonitoring",
                "processPacket",
                "Ağ anomalisi tespit edildi: " + anomaly->description,
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                anomaly->toJson()
            );
        }
    }
    
    // PCAP dosyasına kaydet
    savePacketToPcap(packet_data);
}

bool NetworkMonitoring::shouldCapturePacket(const std::vector<uint8_t>& packet_data) {
    // Paket başlığını ayrıştır
    auto connection = parsePacketHeader(packet_data);
    
    // Hariç tutulan IP'leri kontrol et
    for (const auto& ip : config_.excluded_ips) {
        if (connection.source_ip == ip || connection.destination_ip == ip) {
            return false;
        }
    }
    
    // Protokolleri kontrol et
    if (!config_.protocols.empty()) {
        std::string protocol_str;
        switch (connection.protocol) {
            case NetworkProtocol::TCP: protocol_str = "tcp"; break;
            case NetworkProtocol::UDP: protocol_str = "udp"; break;
            case NetworkProtocol::ICMP: protocol_str = "icmp"; break;
            case NetworkProtocol::HTTP: protocol_str = "http"; break;
            case NetworkProtocol::HTTPS: protocol_str = "https"; break;
            case NetworkProtocol::DNS: protocol_str = "dns"; break;
            case NetworkProtocol::SMTP: protocol_str = "smtp"; break;
            case NetworkProtocol::FTP: protocol_str = "ftp"; break;
            case NetworkProtocol::SSH: protocol_str = "ssh"; break;
            case NetworkProtocol::TELNET: protocol_str = "telnet"; break;
            case NetworkProtocol::OTHER: protocol_str = "other"; break;
        }
        
        bool protocol_found = false;
        for (const auto& protocol : config_.protocols) {
            if (protocol == protocol_str) {
                protocol_found = true;
                break;
            }
        }
        
        if (!protocol_found) {
            return false;
        }
    }
    
    // Portları kontrol et
    if (!config_.ports.empty()) {
        bool port_found = false;
        for (const auto& port : config_.ports) {
            if (connection.source_port == port || connection.destination_port == port) {
                port_found = true;
                break;
            }
        }
        
        if (!port_found) {
            return false;
        }
    }
    
    return true;
}

void NetworkMonitoring::savePacketToPcap(const std::vector<uint8_t>& packet_data) {
    if (config_.pcap_file.empty()) {
        return;
    }
    
    // Maksimum yakalama boyutunu kontrol et
    if (capture_size_ >= config_.max_capture_size) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::WARNING,
                "NetworkMonitoring",
                "savePacketToPcap",
                "Maksimum yakalama boyutuna ulaşıldı: " + std::to_string(config_.max_capture_size),
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
        return;
    }
    
    // Paket boyutunu güncelle
    capture_size_ += packet_data.size();
    
    // Burada gerçek bir PCAP dosyasına yazma işlemi yapılacak
    // Şimdilik sadece log yazıyoruz
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::DEBUG,
            "NetworkMonitoring",
            "savePacketToPcap",
            "Paket PCAP dosyasına kaydedildi: " + std::to_string(packet_data.size()) + " bayt",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
    }
}

std::optional<NetworkAnomaly> NetworkMonitoring::detectAnomaly(const std::vector<uint8_t>& packet_data) {
    // Paket başlığını ayrıştır
    auto connection = parsePacketHeader(packet_data);
    
    // Port taraması tespit et
    if (detectPortScan(connection)) {
        NetworkAnomaly anomaly;
        anomaly.type = NetworkAnomalyType::PORT_SCAN;
        anomaly.description = "Port taraması tespit edildi";
        anomaly.detection_time = std::chrono::system_clock::now();
        anomaly.related_connections.push_back(connection);
        
        nlohmann::json details;
        details["source_ip"] = connection.source_ip;
        details["destination_ip"] = connection.destination_ip;
        details["port_count"] = 10; // Örnek değer
        anomaly.details = details;
        
        return anomaly;
    }
    
    // DoS saldırısı tespit et
    if (detectDosAttack(connection)) {
        NetworkAnomaly anomaly;
        anomaly.type = NetworkAnomalyType::DOS_ATTACK;
        anomaly.description = "DoS saldırısı tespit edildi";
        anomaly.detection_time = std::chrono::system_clock::now();
        anomaly.related_connections.push_back(connection);
        
        nlohmann::json details;
        details["source_ip"] = connection.source_ip;
        details["destination_ip"] = connection.destination_ip;
        details["packet_rate"] = 1000; // Örnek değer
        anomaly.details = details;
        
        return anomaly;
    }
    
    // Brute force saldırısı tespit et
    if (detectBruteForce(connection)) {
        NetworkAnomaly anomaly;
        anomaly.type = NetworkAnomalyType::BRUTE_FORCE;
        anomaly.description = "Brute force saldırısı tespit edildi";
        anomaly.detection_time = std::chrono::system_clock::now();
        anomaly.related_connections.push_back(connection);
        
        nlohmann::json details;
        details["source_ip"] = connection.source_ip;
        details["destination_ip"] = connection.destination_ip;
        details["attempt_count"] = 100; // Örnek değer
        anomaly.details = details;
        
        return anomaly;
    }
    
    // Veri sızıntısı tespit et
    if (detectDataExfiltration(connection)) {
        NetworkAnomaly anomaly;
        anomaly.type = NetworkAnomalyType::DATA_EXFILTRATION;
        anomaly.description = "Veri sızıntısı tespit edildi";
        anomaly.detection_time = std::chrono::system_clock::now();
        anomaly.related_connections.push_back(connection);
        
        nlohmann::json details;
        details["source_ip"] = connection.source_ip;
        details["destination_ip"] = connection.destination_ip;
        details["data_size"] = connection.bytes_sent;
        anomaly.details = details;
        
        return anomaly;
    }
    
    return std::nullopt;
}

std::vector<NetworkConnection> NetworkMonitoring::getActiveConnections() const {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    return active_connections_;
}

std::vector<NetworkConnection> NetworkMonitoring::getConnectionHistory(int limit) const {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    
    if (limit <= 0 || limit >= static_cast<int>(connection_history_.size())) {
        return connection_history_;
    }
    
    return std::vector<NetworkConnection>(
        connection_history_.end() - limit,
        connection_history_.end()
    );
}

std::vector<NetworkAnomaly> NetworkMonitoring::getAnomalyHistory(int limit) const {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    
    if (limit <= 0 || limit >= static_cast<int>(anomaly_history_.size())) {
        return anomaly_history_;
    }
    
    return std::vector<NetworkAnomaly>(
        anomaly_history_.end() - limit,
        anomaly_history_.end()
    );
}

NetworkConnection NetworkMonitoring::parsePacketHeader(const std::vector<uint8_t>& packet_data) {
    // Burada gerçek bir paket başlığı ayrıştırma işlemi yapılacak
    // Şimdilik örnek bir bağlantı döndürüyoruz
    
    NetworkConnection connection;
    connection.source_ip = "192.168.1.100";
    connection.source_port = 12345;
    connection.destination_ip = "192.168.1.1";
    connection.destination_port = 80;
    connection.protocol = NetworkProtocol::TCP;
    connection.start_time = std::chrono::system_clock::now();
    connection.bytes_sent = 1024;
    connection.bytes_received = 2048;
    connection.process_name = "browser";
    connection.pid = 1234;
    connection.user = "user";
    connection.connection_state = "ESTABLISHED";
    
    return connection;
}

bool NetworkMonitoring::detectPortScan(const NetworkConnection& connection) {
    // Burada gerçek bir port taraması tespiti yapılacak
    // Şimdilik örnek bir değer döndürüyoruz
    return false;
}

bool NetworkMonitoring::detectDosAttack(const NetworkConnection& connection) {
    // Burada gerçek bir DoS saldırısı tespiti yapılacak
    // Şimdilik örnek bir değer döndürüyoruz
    return false;
}

bool NetworkMonitoring::detectBruteForce(const NetworkConnection& connection) {
    // Burada gerçek bir brute force saldırısı tespiti yapılacak
    // Şimdilik örnek bir değer döndürüyoruz
    return false;
}

bool NetworkMonitoring::detectDataExfiltration(const NetworkConnection& connection) {
    // Burada gerçek bir veri sızıntısı tespiti yapılacak
    // Şimdilik örnek bir değer döndürüyoruz
    return false;
}

} // namespace monitoring
} // namespace security_agent 