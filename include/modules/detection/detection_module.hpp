#pragma once

#include <string>
#include <memory>
#include <nlohmann/json.hpp>

namespace security_agent {
namespace detection {

// Detection modülü
class DetectionModule {
public:
    DetectionModule(const std::string& config_path);
    virtual ~DetectionModule();
    
    // Tehditleri tespit et
    virtual void detectThreats(const nlohmann::json& data);
    
    // Yapılandırmayı yeniden yükle
    virtual void reloadConfig();
    
private:
    // Yapılandırma dosyası yolu
    std::string config_path_;
};

} // namespace detection
} // namespace security_agent 