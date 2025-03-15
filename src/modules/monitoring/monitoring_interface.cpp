#include "modules/monitoring/monitoring_interface.hpp"
#include "modules/event_management/event_manager.hpp"
#include "modules/logging/logging_module.hpp"
#include "modules/routing/routing_module.hpp"
#include "modules/detection/detection_module.hpp"
#include <yaml-cpp/yaml.h>
#include <iostream>
#include <stdexcept>

namespace security_agent {
namespace monitoring {

// MonitoringEvents sınıfı implementasyonu
MonitoringEvents::MonitoringEvents(const std::string& monitoring_type, 
                                 const std::string& message,
                                 MonitoringEventType event_type)
    : monitoring_type_(monitoring_type), message_(message), event_type_(event_type) {
}

nlohmann::json MonitoringEvents::toJson() const {
    nlohmann::json json;
    json["monitoring_type"] = monitoring_type_;
    json["message"] = message_;
    
    // Event tipini string'e çevir
    std::string event_type_str;
    switch (event_type_) {
        case MonitoringEventType::MONITORING_STARTED:
            event_type_str = "MONITORING_STARTED";
            break;
        case MonitoringEventType::MONITORING_STOPPED:
            event_type_str = "MONITORING_STOPPED";
            break;
        case MonitoringEventType::MONITORING_ERROR:
            event_type_str = "MONITORING_ERROR";
            break;
        case MonitoringEventType::MONITORING_RESTARTED:
            event_type_str = "MONITORING_RESTARTED";
            break;
    }
    
    json["event_type"] = event_type_str;
    json["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    return json;
}

// MonitoringInterface sınıfı implementasyonu
MonitoringInterface::MonitoringInterface(
    const std::string& config_path,
    std::shared_ptr<event_management::EventManager> event_manager,
    std::shared_ptr<logging::LoggingModule> logging_module,
    std::shared_ptr<routing::RoutingModule> routing_module,
    std::shared_ptr<detection::DetectionModule> detection_module
) : config_path_(config_path),
    event_manager_(event_manager),
    logging_module_(logging_module),
    routing_module_(routing_module),
    detection_module_(detection_module),
    running_(false) {
    
    loadConfig();
}

MonitoringInterface::~MonitoringInterface() {
    stop();
}

void MonitoringInterface::stop() {
    running_ = false;
}

void MonitoringInterface::loadConfig() {
    try {
        YAML::Node config = YAML::LoadFile(config_path_);
        
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::INFO,
                "MonitoringInterface",
                "loadConfig",
                "Yapılandırma dosyası yüklendi: " + config_path_,
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
                "MonitoringInterface",
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

bool MonitoringInterface::sendData(const nlohmann::json& data, const std::string& index_name) {
    if (!routing_module_) {
        return false;
    }
    
    auto result = routing_module_->sendData(data, index_name);
    
    if (result != routing::SendResult::SUCCESS) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::ERROR,
                "MonitoringInterface",
                "sendData",
                "Veri gönderilemedi: " + std::to_string(static_cast<int>(result)),
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                data
            );
        }
        return false;
    }
    
    return true;
}

nlohmann::json MonitoringInterface::createResponse(const nlohmann::json& data, const std::string& type) {
    nlohmann::json response;
    response["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    response["type"] = type;
    response["data"] = data;
    
    return response;
}

} // namespace monitoring
} // namespace security_agent 