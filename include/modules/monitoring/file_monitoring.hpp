#pragma once

#include "modules/monitoring/monitoring_interface.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <optional>
#include <filesystem>
#include <thread>
#include <nlohmann/json.hpp>

namespace security_agent {
namespace monitoring {

/**
 * @brief Dosya bilgisi
 */
struct FileInfo {
    std::string path;
    std::string name;
    std::string extension;
    uint64_t size;
    std::chrono::system_clock::time_point last_modified;
    std::string hash;
    std::string owner;
    int permissions;
    bool is_directory;
    bool is_symlink;
    std::optional<std::string> target_path; // Sembolik bağlantı hedefi
    
    /**
     * @brief Dosya bilgisini JSON formatına dönüştürür
     * 
     * @return JSON formatında dosya bilgisi
     */
    nlohmann::json toJson() const;
};

/**
 * @brief Dosya değişikliği bilgisi
 */
struct FileChanges {
    bool content_changed = false;
    bool size_changed = false;
    bool permissions_changed = false;
    bool owner_changed = false;
    std::optional<uint64_t> old_size;
    std::optional<uint64_t> new_size;
    std::optional<int> old_permissions;
    std::optional<int> new_permissions;
    std::optional<std::string> old_owner;
    std::optional<std::string> new_owner;
};

/**
 * @brief Dosya olayı türü
 */
enum class FileEventType {
    CREATED,
    MODIFIED,
    DELETED,
    RENAMED,
    PERMISSION_CHANGED,
    OWNER_CHANGED,
    ACCESSED,
    MOVED,
    OTHER
};

/**
 * @brief Dosya olayı bilgisi
 */
struct FileEvent {
    FileEventType type;
    FileInfo file;
    std::chrono::system_clock::time_point timestamp;
    std::optional<FileChanges> changes;
    std::optional<std::string> old_path; // Yeniden adlandırma için
    
    /**
     * @brief Dosya olayını JSON formatına dönüştürür
     * 
     * @return JSON formatında dosya olayı
     */
    nlohmann::json toJson() const;
};

/**
 * @brief İzlenen dizin bilgisi
 */
struct MonitoredDirectory {
    std::string path;
    bool recursive;
    std::vector<std::string> extensions;
};

/**
 * @brief Dosya izleme yapılandırması
 */
struct FileMonitoringConfig {
    bool enabled = true;
    int scan_interval = 60; // saniye
    std::vector<MonitoredDirectory> monitored_directories;
    std::vector<std::string> monitored_files;
    std::vector<std::string> excluded_directories;
    std::vector<std::string> excluded_files;
    int cache_size = 1000;
    std::vector<std::string> suspicious_extensions;
    uint64_t max_file_size = 100 * 1024 * 1024; // 100 MB
};

/**
 * @brief Dosya izleme sınıfı
 */
class FileMonitoring : public MonitoringInterface {
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
    FileMonitoring(
        const std::string& config_path,
        std::shared_ptr<event_management::EventManager> event_manager,
        std::shared_ptr<logging::LoggingModule> logging_module,
        std::shared_ptr<routing::RoutingModule> routing_module,
        std::shared_ptr<detection::DetectionModule> detection_module
    );
    
    /**
     * @brief Yıkıcı fonksiyon
     */
    ~FileMonitoring();
    
    /**
     * @brief İzleme işlemini başlatır
     */
    void monitor() override;
    
    /**
     * @brief Yapılandırmayı yükler
     */
    void loadConfig() override;
    
    /**
     * @brief İzlenen dizinleri döndürür
     * 
     * @return Dizin listesi
     */
    const std::vector<MonitoredDirectory>& getMonitoredDirectories() const;
    
    /**
     * @brief Dizini tarar
     * 
     * @param directory_path Dizin yolu
     * @param recursive Alt dizinleri de tara
     * @return Dosya listesi
     */
    std::vector<FileInfo> scanDirectory(const std::string& directory_path, bool recursive = false);
    
    /**
     * @brief Dosya bilgisini JSON formatına dönüştürür
     * 
     * @param file Dosya bilgisi
     * @return JSON formatında dosya bilgisi
     */
    nlohmann::json fileInfoToJson(const FileInfo& file);
    
    /**
     * @brief Dosya hash değerini hesaplar
     * 
     * @param file_path Dosya yolu
     * @return Hash değeri
     */
    std::string calculateFileHash(const std::string& file_path);
    
    /**
     * @brief Dosya değişikliklerini tespit eder
     * 
     * @param old_info Eski dosya bilgisi
     * @param new_info Yeni dosya bilgisi
     * @return Değişiklik varsa true, yoksa false
     */
    bool detectFileChanges(const FileInfo& old_info, const FileInfo& new_info);
    
    /**
     * @brief Dosyanın şüpheli olup olmadığını kontrol eder
     * 
     * @param file Dosya bilgisi
     * @return Şüpheli ise true, değilse false
     */
    bool isSuspiciousFile(const FileInfo& file);
    
    /**
     * @brief Dosyanın hariç tutulup tutulmadığını kontrol eder
     * 
     * @param file Dosya bilgisi
     * @return Hariç tutuluyorsa true, değilse false
     */
    bool isExcludedFile(const FileInfo& file);
    
    /**
     * @brief Dosya olayını işler
     * 
     * @param event Dosya olayı
     */
    void handleFileEvent(const FileEvent& event);
    
    /**
     * @brief Dosya olayı geçmişini döndürür
     * 
     * @param limit Maksimum kayıt sayısı
     * @return Olay listesi
     */
    std::vector<FileEvent> getFileEventHistory(int limit = 100) const;
    
private:
    /**
     * @brief Dosya bilgisini alır
     * 
     * @param file_path Dosya yolu
     * @return Dosya bilgisi
     */
    FileInfo getFileInfo(const std::string& file_path);
    
    /**
     * @brief Dosya olayı oluşturur
     * 
     * @param type Olay türü
     * @param file Dosya bilgisi
     * @param changes Değişiklik bilgisi
     * @param old_path Eski dosya yolu
     * @return Dosya olayı
     */
    FileEvent createFileEvent(
        FileEventType type,
        const FileInfo& file,
        const std::optional<FileChanges>& changes = std::nullopt,
        const std::optional<std::string>& old_path = std::nullopt
    );
    
    /**
     * @brief Dosya olayı oluşturur
     * 
     * @param event Dosya olayı
     */
    void raiseFileEvent(const FileEvent& event);
    
    void startMonitoring();
    void stopMonitoring();
    void scanDirectory(const MonitoredDirectory& dir);
    bool shouldScanFile(const std::string& file_path, const std::vector<std::string>& extensions);
    void scanFile(const std::string& file_path);
    void handleNewFile(const FileInfo& file_info);
    void handleModifiedFile(const FileInfo& file_info);
    void handleDeletedFile(const std::string& file_path);
    std::vector<FileEvent> getFileEvents(int limit = 100) const;
    std::vector<FileInfo> getMonitoredFiles() const;
    
    FileMonitoringConfig config_;
    mutable std::mutex file_mutex_;
    std::unordered_map<std::string, FileInfo> file_cache_;
    std::vector<FileEvent> file_events_;
    bool monitoring_;
    std::thread monitoring_thread_;
};

} // namespace monitoring
} // namespace security_agent 