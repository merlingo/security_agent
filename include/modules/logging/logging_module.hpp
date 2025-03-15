#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <optional>
#include <nlohmann/json.hpp>

namespace security_agent {
namespace logging {

/**
 * @brief Log seviyesi
 */
enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

/**
 * @brief Günlük modülü yapılandırması
 */
struct LoggingConfig {
    bool enabled = true;
    bool console_logging = true;
    bool file_logging = true;
    bool syslog_logging = false;
    bool daily_rotation = true;
    LogLevel min_level = LogLevel::INFO;
    std::string default_log_file;
    std::unordered_set<std::string> modules;
    std::unordered_map<std::string, std::string> module_files;
};

/**
 * @brief Günlük modülü
 */
class LoggingModule {
public:
    /**
     * @brief Yapıcı fonksiyon
     * 
     * @param config_path Yapılandırma dosyasının yolu
     */
    LoggingModule(const std::string& config_path);
    
    /**
     * @brief Yıkıcı fonksiyon
     */
    ~LoggingModule();
    
    /**
     * @brief Log kaydı oluşturur
     * 
     * @param level Log seviyesi
     * @param module Modül adı
     * @param function Fonksiyon adı
     * @param message Log mesajı
     * @param file Kaynak dosya
     * @param func Kaynak fonksiyon
     * @param line Kaynak satır
     * @param data Ek veri
     */
    void log(
        LogLevel level,
        const std::string& module,
        const std::string& function,
        const std::string& message,
        const std::string& file,
        const std::string& func,
        const std::string& line,
        const std::optional<nlohmann::json>& data = std::nullopt
    );
    
    /**
     * @brief Yapılandırmayı yeniden yükler
     */
    void reloadConfig();
    
    /**
     * @brief Modül günlüğünün etkin olup olmadığını kontrol eder
     * 
     * @param module Modül adı
     * @return Etkin ise true, değilse false
     */
    bool isModuleLoggingEnabled(const std::string& module) const;
    
    /**
     * @brief Modül için log dosyasını döndürür
     * 
     * @param module Modül adı
     * @return Log dosyası yolu
     */
    std::optional<std::string> getModuleLogFile(const std::string& module) const;
    
private:
    /**
     * @brief Log seviyesini metin olarak döndürür
     * 
     * @param level Log seviyesi
     * @return Log seviyesi metni
     */
    std::string getLevelString(LogLevel level) const;
    
    /**
     * @brief Geçerli zaman damgasını döndürür
     * 
     * @return Zaman damgası
     */
    std::string getCurrentTimestamp() const;
    
    /**
     * @brief Yapılandırmayı yükler
     */
    void loadConfig();
    
    std::string config_path_;
    LoggingConfig config_;
    std::unordered_map<std::string, std::ofstream> log_streams_;
};

} // namespace logging
} // namespace security_agent 