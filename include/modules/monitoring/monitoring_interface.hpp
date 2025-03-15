#pragma once

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>
#include <optional>

namespace security_agent {

// İleri bildirimler
namespace event_management {
class EventManager;
}

namespace logging {
class LoggingModule;
}

namespace routing {
class RoutingModule;
enum class SendResult;
}

namespace detection {
class DetectionModule;
}

namespace monitoring {

// Monitoring olayları için enum
enum class MonitoringEventType {
    MONITORING_STARTED,
    MONITORING_STOPPED,
    MONITORING_ERROR,
    MONITORING_RESTARTED
};

// Monitoring yapılandırması
struct MonitoringConfig {
    bool enabled = true;
    int interval = 60; // saniye
    
    struct {
        bool enabled = true;
        bool ai_detection_enabled = false;
        bool anomaly_detection_enabled = false;
    } detection;
};

// Monitoring olayları
class MonitoringEvents {
public:
    MonitoringEvents(const std::string& monitoring_type, 
                    const std::string& message,
                    MonitoringEventType event_type);
    
    std::string getMonitoringType() const { return monitoring_type_; }
    std::string getMessage() const { return message_; }
    MonitoringEventType getEventType() const { return event_type_; }
    
    nlohmann::json toJson() const;
    
private:
    std::string monitoring_type_;
    std::string message_;
    MonitoringEventType event_type_;
};

/**
 * @brief Tüm izleme modülleri için temel arayüz sınıfı
 */
class MonitoringInterface {
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
    MonitoringInterface(
        const std::string& config_path,
        std::shared_ptr<event_management::EventManager> event_manager,
        std::shared_ptr<logging::LoggingModule> logging_module,
        std::shared_ptr<routing::RoutingModule> routing_module,
        std::shared_ptr<detection::DetectionModule> detection_module
    );
    
    /**
     * @brief Sanal yıkıcı fonksiyon
     */
    virtual ~MonitoringInterface();
    
    /**
     * @brief İzleme işlemini başlatır
     */
    virtual void monitor() = 0;
    
    /**
     * @brief İzleme işlemini durdurur
     */
    virtual void stop();
    
    /**
     * @brief Yapılandırmayı yükler
     */
    virtual void loadConfig();
    
    /**
     * @brief Veriyi yönlendirme modülüne gönderir
     * 
     * @param data Gönderilecek veri
     * @param index_name Hedef indeks adı
     * @return Gönderim sonucu
     */
    virtual bool sendData(const nlohmann::json& data, const std::string& index_name);
    
    /**
     * @brief Tehdit algılama için yanıt oluşturur
     * 
     * @param data Tehdit verisi
     * @param type Tehdit türü
     * @return Yanıt JSON'ı
     */
    virtual nlohmann::json createResponse(const nlohmann::json& data, const std::string& type);

protected:
    std::string config_path_;
    std::shared_ptr<event_management::EventManager> event_manager_;
    std::shared_ptr<logging::LoggingModule> logging_module_;
    std::shared_ptr<routing::RoutingModule> routing_module_;
    std::shared_ptr<detection::DetectionModule> detection_module_;
    bool running_;
};

} // namespace monitoring
} // namespace security_agent 