#include "modules/event_management/event.hpp"
#include <openssl/hmac.h>
#include <iomanip>
#include <sstream>

namespace security_agent {
namespace event_management {

Event::Event(EventType type,
             const std::string& source_module,
             SeverityLevel severity,
             const nlohmann::json& payload)
    : type_(type)
    , timestamp_(std::chrono::system_clock::now())
    , source_module_(source_module)
    , severity_(severity)
    , payload_(payload) {}

nlohmann::json Event::toJson() const {
    nlohmann::json j;
    j["type"] = static_cast<int>(type_);
    j["timestamp"] = std::chrono::system_clock::to_time_t(timestamp_);
    j["source_module"] = source_module_;
    j["severity"] = static_cast<int>(severity_);
    j["payload"] = payload_;
    return j;
}

Event Event::fromJson(const nlohmann::json& json) {
    EventType type = static_cast<EventType>(json["type"].get<int>());
    std::string source_module = json["source_module"].get<std::string>();
    SeverityLevel severity = static_cast<SeverityLevel>(json["severity"].get<int>());
    nlohmann::json payload = json["payload"];
    
    return Event(type, source_module, severity, payload);
}

std::string Event::sign(const std::string& secret_key) const {
    nlohmann::json j = this->toJson();
    std::string message = j.dump();
    
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    
    HMAC(EVP_sha256(),
         secret_key.c_str(), static_cast<int>(secret_key.length()),
         reinterpret_cast<const unsigned char*>(message.c_str()),
         message.length(),
         hmac,
         &hmac_len);
    
    std::stringstream ss;
    for(unsigned int i = 0; i < hmac_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hmac[i]);
    }
    
    return ss.str();
}

bool Event::verifySignature(const std::string& signature, const std::string& secret_key) const {
    std::string computed_signature = sign(secret_key);
    return computed_signature == signature;
}

} // namespace event_management
} // namespace security_agent 