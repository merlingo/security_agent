#ifndef SECURITY_AGENT_ROUTING_MODULE_HPP
#define SECURITY_AGENT_ROUTING_MODULE_HPP

#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <chrono>
#include <nlohmann/json.hpp>

namespace security_agent {
namespace routing {

// Hedef türleri
enum class DestinationType {
    ELASTICSEARCH,
    LOGSTASH,
    RABBITMQ,
    FILE,
    CUSTOM
};

// Gönderim sonucu
enum class SendResult {
    SUCCESS,
    FAILURE,
    RETRY,
    QUEUE_FULL,
    INVALID_DATA,
    CONNECTION_ERROR,
    AUTHENTICATION_ERROR,
    TIMEOUT
};

// Sunucu yapılandırması
struct ServerConfig {
    std::string host;
    int port;
    std::string username;
    std::string password;
    bool use_ssl;
    std::string ca_cert_path;
};

// Yönlendirme yapılandırması
struct RoutingConfig {
    bool enabled;
    int retry_count;
    int retry_delay_seconds;
    int queue_size_limit;
    int batch_size;
    int processing_interval_seconds;
    ServerConfig server;
    std::unordered_map<std::string, DestinationType> destinations;
};

// İndeks yapılandırması
struct IndexConfig {
    std::string name;
    DestinationType destination_type;
    std::string destination_url;
    std::string mapping;
    bool use_timestamp;
    std::string timestamp_field;
    std::string index_pattern;
};

// Kuyruk öğesi
struct QueueItem {
    nlohmann::json data;
    std::string index;
    int retry_count;
    std::chrono::system_clock::time_point timestamp;
};

/**
 * @brief Yönlendirme modülü
 * 
 * Bu modül, verileri farklı hedeflere yönlendirmek için kullanılır.
 * Elasticsearch, Logstash, RabbitMQ, dosya ve özel hedefler desteklenir.
 */
class RoutingModule {
public:
    /**
     * @brief Yapılandırıcı
     * 
     * @param config_path Yapılandırma dosyasının yolu
     */
    RoutingModule(const std::string& config_path);
    
    /**
     * @brief Yıkıcı
     */
    ~RoutingModule();
    
    /**
     * @brief Veri gönder
     * 
     * @param data Gönderilecek veri
     * @param index Hedef indeks
     * @return SendResult Gönderim sonucu
     */
    SendResult sendData(const nlohmann::json& data, const std::string& index);
    
    /**
     * @brief Yapılandırmayı yeniden yükle
     */
    void reloadConfig();
    
    /**
     * @brief İndeksin yapılandırılıp yapılandırılmadığını kontrol et
     * 
     * @param index İndeks adı
     * @return true İndeks yapılandırılmış
     * @return false İndeks yapılandırılmamış
     */
    bool isIndexConfigured(const std::string& index) const {
        return index_configs_.find(index) != index_configs_.end();
    }
    
private:
    /**
     * @brief Yapılandırmayı yükle
     */
    void loadConfig();
    
    /**
     * @brief İşleme iş parçacığı
     */
    void processingThread();
    
    /**
     * @brief Veriyi dahili olarak gönder
     * 
     * @param data Gönderilecek veri
     * @param index Hedef indeks
     * @return SendResult Gönderim sonucu
     */
    SendResult sendDataInternal(const nlohmann::json& data, const std::string& index);
    
    /**
     * @brief Elasticsearch'e gönder
     * 
     * @param data Gönderilecek veri
     * @param index_config İndeks yapılandırması
     * @return SendResult Gönderim sonucu
     */
    SendResult sendToElasticsearch(const nlohmann::json& data, const IndexConfig& index_config);
    
    /**
     * @brief Logstash'e gönder
     * 
     * @param data Gönderilecek veri
     * @param index_config İndeks yapılandırması
     * @return SendResult Gönderim sonucu
     */
    SendResult sendToLogstash(const nlohmann::json& data, const IndexConfig& index_config);
    
    /**
     * @brief RabbitMQ'ya gönder
     * 
     * @param data Gönderilecek veri
     * @param index_config İndeks yapılandırması
     * @return SendResult Gönderim sonucu
     */
    SendResult sendToRabbitMQ(const nlohmann::json& data, const IndexConfig& index_config);
    
    /**
     * @brief Dosyaya gönder
     * 
     * @param data Gönderilecek veri
     * @param index_config İndeks yapılandırması
     * @return SendResult Gönderim sonucu
     */
    SendResult sendToFile(const nlohmann::json& data, const IndexConfig& index_config);
    
    /**
     * @brief Özel hedefe gönder
     * 
     * @param data Gönderilecek veri
     * @param index_config İndeks yapılandırması
     * @return SendResult Gönderim sonucu
     */
    SendResult sendToCustom(const nlohmann::json& data, const IndexConfig& index_config);
    
    // Yapılandırma dosyasının yolu
    std::string config_path_;
    
    // Yapılandırma
    RoutingConfig config_;
    
    // İndeks yapılandırmaları
    std::unordered_map<std::string, IndexConfig> index_configs_;
    
    // Veri kuyruğu
    std::queue<QueueItem> data_queue_;
    
    // Kuyruk mutex'i
    std::mutex queue_mutex_;
    
    // Kuyruk koşul değişkeni
    std::condition_variable queue_cv_;
    
    // İşleme iş parçacığı
    std::thread processing_thread_;
    
    // Durma bayrağı
    std::atomic<bool> should_stop_;
};

} // namespace routing
} // namespace security_agent

#endif // SECURITY_AGENT_ROUTING_MODULE_HPP 