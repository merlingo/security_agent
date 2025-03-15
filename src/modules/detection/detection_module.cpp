#include "modules/detection/detection_module.hpp"
#include <iostream>
#include <yaml-cpp/yaml.h>

namespace security_agent {
namespace detection {

DetectionModule::DetectionModule(const std::string& config_path)
    : config_path_(config_path) {
    // Yapılandırmayı yükle
    reloadConfig();
}

DetectionModule::~DetectionModule() {
    // Temizlik işlemleri
}

void DetectionModule::detectThreats(const nlohmann::json& data) {
    // Tehdit algılama işlemleri
    // Bu örnek implementasyonda sadece veriyi yazdırıyoruz
    std::cout << "Tehdit algılama: " << data.dump(2) << std::endl;
}

void DetectionModule::reloadConfig() {
    try {
        // Yapılandırma dosyasını yükle
        YAML::Node config = YAML::LoadFile(config_path_);
        
        // Yapılandırma işlemleri
    } catch (const std::exception& e) {
        std::cerr << "Tehdit algılama yapılandırması yüklenemedi: " << e.what() << std::endl;
    }
}

} // namespace detection
} // namespace security_agent 