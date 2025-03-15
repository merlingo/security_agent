#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <mutex>
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

namespace behavior {

/**
 * @brief Davranış tespiti için kural tipi
 */
enum class RuleType {
    SIGMA,  ///< Sigma kuralları (log analizi)
    YARA,   ///< Yara kuralları (dosya analizi)
    SNORT   ///< Snort kuralları (ağ analizi)
};

/**
 * @brief Repo güncelleme stratejisi
 */
enum class UpdateStrategy {
    AUTO,        ///< Otomatik güncelleme
    USER_DEFINED, ///< Kullanıcı tanımlı zamanlarda güncelleme
    MANUAL,      ///< Manuel güncelleme
    NEVER        ///< Asla güncelleme
};

/**
 * @brief Repo bilgisi
 */
struct RepoInfo {
    std::string name;                  ///< Repo adı
    std::string url;                   ///< Repo URL'i
    std::string local_path;            ///< Lokal dizin yolu
    RuleType rule_type;                ///< Kural tipi
    UpdateStrategy update_strategy;    ///< Güncelleme stratejisi
    std::chrono::system_clock::time_point last_update; ///< Son güncelleme zamanı
    std::string version;               ///< Repo versiyonu
    bool is_critical;                  ///< Kritik öneme sahip mi
};

/**
 * @brief Tehdit bilgisi
 */
struct ThreatInfo {
    std::string rule_id;               ///< Kural ID'si
    std::string rule_name;             ///< Kural adı
    std::string description;           ///< Açıklama
    std::string severity;              ///< Şiddet
    RuleType rule_type;                ///< Kural tipi
    std::string repo_name;             ///< Repo adı
    std::chrono::system_clock::time_point detection_time; ///< Tespit zamanı
    nlohmann::json details;            ///< Detaylar
};

/**
 * @brief Davranış modülü yapılandırması
 */
struct BehaviorConfig {
    bool enabled = true;                ///< Modül etkin mi
    std::vector<RepoInfo> repos;        ///< Repolar
    std::unordered_map<std::string, std::vector<RuleType>> service_rules; ///< Servis bazlı kural tipleri
    std::chrono::seconds update_check_interval = std::chrono::hours(24); ///< Güncelleme kontrol aralığı
};

/**
 * @brief Davranış modülü
 */
class BehaviorModule {
public:
    /**
     * @brief Yapıcı fonksiyon
     * 
     * @param config_path Yapılandırma dosyasının yolu
     * @param event_manager Olay yöneticisi
     * @param logging_module Günlük modülü
     */
    BehaviorModule(
        const std::string& config_path,
        std::shared_ptr<event_management::EventManager> event_manager,
        std::shared_ptr<logging::LoggingModule> logging_module
    );
    
    /**
     * @brief Yıkıcı fonksiyon
     */
    ~BehaviorModule();
    
    /**
     * @brief Yapılandırmayı yükler
     */
    void loadConfig();
    
    /**
     * @brief Repoları günceller
     * 
     * @param force Zorla güncelleme
     * @return Güncelleme başarılı mı
     */
    bool updateRepos(bool force = false);
    
    /**
     * @brief Belirli bir repoyu günceller
     * 
     * @param repo_name Repo adı
     * @param force Zorla güncelleme
     * @return Güncelleme başarılı mı
     */
    bool updateRepo(const std::string& repo_name, bool force = false);
    
    /**
     * @brief Log verisi üzerinde davranış tespiti yapar
     * 
     * @param service_name Servis adı
     * @param log_data Log verisi
     * @return Tespit edilen tehditler
     */
    std::vector<ThreatInfo> detectLogThreats(const std::string& service_name, const nlohmann::json& log_data);
    
    /**
     * @brief Dosya üzerinde davranış tespiti yapar
     * 
     * @param service_name Servis adı
     * @param file_path Dosya yolu
     * @return Tespit edilen tehditler
     */
    std::vector<ThreatInfo> detectFileThreats(const std::string& service_name, const std::string& file_path);
    
    /**
     * @brief Ağ paketi üzerinde davranış tespiti yapar
     * 
     * @param service_name Servis adı
     * @param packet_data Paket verisi
     * @return Tespit edilen tehditler
     */
    std::vector<ThreatInfo> detectNetworkThreats(const std::string& service_name, const std::vector<uint8_t>& packet_data);
    
    /**
     * @brief Servis için kullanılan kural tiplerini döndürür
     * 
     * @param service_name Servis adı
     * @return Kural tipleri
     */
    std::vector<RuleType> getServiceRuleTypes(const std::string& service_name) const;
    
    /**
     * @brief Repoları döndürür
     * 
     * @return Repolar
     */
    const std::vector<RepoInfo>& getRepos() const;
    
    /**
     * @brief Modülün etkin olup olmadığını kontrol eder
     * 
     * @return Etkin ise true, değilse false
     */
    bool isEnabled() const;
    
private:
    /**
     * @brief Sigma kurallarını çalıştırır
     * 
     * @param log_data Log verisi
     * @return Tespit edilen tehditler
     */
    std::vector<ThreatInfo> runSigmaRules(const nlohmann::json& log_data);
    
    /**
     * @brief Yara kurallarını çalıştırır
     * 
     * @param file_path Dosya yolu
     * @return Tespit edilen tehditler
     */
    std::vector<ThreatInfo> runYaraRules(const std::string& file_path);
    
    /**
     * @brief Snort kurallarını çalıştırır
     * 
     * @param packet_data Paket verisi
     * @return Tespit edilen tehditler
     */
    std::vector<ThreatInfo> runSnortRules(const std::vector<uint8_t>& packet_data);
    
    /**
     * @brief Repoyu klonlar
     * 
     * @param repo Repo bilgisi
     * @return Klonlama başarılı mı
     */
    bool cloneRepo(const RepoInfo& repo);
    
    /**
     * @brief Repoyu günceller
     * 
     * @param repo Repo bilgisi
     * @return Güncelleme başarılı mı
     */
    bool pullRepo(RepoInfo& repo);
    
    /**
     * @brief Repo versiyonunu alır
     * 
     * @param repo Repo bilgisi
     * @return Repo versiyonu
     */
    std::string getRepoVersion(const RepoInfo& repo);
    
    /**
     * @brief Tehdit olayı oluşturur
     * 
     * @param threat Tehdit bilgisi
     */
    void raiseThreatEvent(const ThreatInfo& threat);
    
    std::string config_path_;
    std::shared_ptr<event_management::EventManager> event_manager_;
    std::shared_ptr<logging::LoggingModule> logging_module_;
    BehaviorConfig config_;
    std::mutex repo_mutex_;
    std::chrono::system_clock::time_point last_update_check_;
};

} // namespace behavior
} // namespace security_agent 