#pragma once

#include <string>
#include <chrono>
#include <nlohmann/json.hpp>

namespace security_agent {
namespace event_management {

enum class EventType {
    // Monitoring Events
    PROCESS_STARTED,
    FILE_ACCESSED,
    NETWORK_CONNECTION,
    
    // Detection Events
    MALWARE_DETECTED,
    ANOMALY_DETECTED,
    
    // Response Actions
    PROCESS_TERMINATED,
    QUARANTINE_COMPLETED,
    RESPONSE_ACTION
};

enum class SeverityLevel {
    INFO,
    WARNING,
    CRITICAL
};

class Event {
public:
    Event(EventType type,
          const std::string& source_module,
          SeverityLevel severity,
          const nlohmann::json& payload);
    
    // Getters
    EventType getType() const { return type_; }
    std::chrono::system_clock::time_point getTimestamp() const { return timestamp_; }
    std::string getSourceModule() const { return source_module_; }
    SeverityLevel getSeverity() const { return severity_; }
    nlohmann::json getPayload() const { return payload_; }
    
    // Serialize/Deserialize
    nlohmann::json toJson() const;
    static Event fromJson(const nlohmann::json& json);
    
    // Message signing
    std::string sign(const std::string& secret_key) const;
    bool verifySignature(const std::string& signature, const std::string& secret_key) const;

private:
    EventType type_;
    std::chrono::system_clock::time_point timestamp_;
    std::string source_module_;
    SeverityLevel severity_;
    nlohmann::json payload_;
};

} // namespace event_management
} // namespace security_agent 