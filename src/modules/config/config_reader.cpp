#include "modules/config/config_reader.hpp"
#include <stdexcept>
#include <filesystem>

namespace security_agent {
namespace config {

ConfigReader::ConfigReader(const std::string& config_path)
    : config_path_(config_path) {
    loadConfig();
}

void ConfigReader::loadConfig() {
    if (!std::filesystem::exists(config_path_)) {
        throw std::runtime_error("Yapılandırma dosyası bulunamadı: " + config_path_);
    }

    try {
        config_ = YAML::LoadFile(config_path_);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("YAML yapılandırma dosyası yüklenirken hata: " + std::string(e.what()));
    }
}

YAML::Node ConfigReader::getModuleConfig(const std::string& module_name) const {
    if (!config_["modules"] || !config_["modules"][module_name]) {
        throw std::runtime_error("Modül yapılandırması bulunamadı: " + module_name);
    }
    return config_["modules"][module_name];
}

YAML::Node ConfigReader::getGeneralConfig() const {
    if (!config_["general"]) {
        throw std::runtime_error("Genel yapılandırma bulunamadı");
    }
    return config_["general"];
}

void ConfigReader::reloadConfig() {
    loadConfig();
}

} // namespace config
} // namespace security_agent 