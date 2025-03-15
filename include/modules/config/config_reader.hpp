#pragma once

#include <string>
#include <memory>
#include <yaml-cpp/yaml.h>

namespace security_agent {
namespace config {

class ConfigReader {
public:
    ConfigReader(const std::string& config_path);
    ~ConfigReader() = default;

    // Belirli bir modülün yapılandırmasını almak için
    YAML::Node getModuleConfig(const std::string& module_name) const;
    
    // Genel yapılandırma ayarlarını almak için
    YAML::Node getGeneralConfig() const;

    // Yapılandırma dosyasının yeniden yüklenmesi için
    void reloadConfig();

private:
    std::string config_path_;
    YAML::Node config_;

    void loadConfig();
};

} // namespace config
} // namespace security_agent 