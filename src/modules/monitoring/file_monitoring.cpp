#include "modules/monitoring/file_monitoring.hpp"
#include "modules/event_management/event_manager.hpp"
#include "modules/logging/logging_module.hpp"
#include "modules/routing/routing_module.hpp"
#include "modules/detection/detection_module.hpp"
#include <yaml-cpp/yaml.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <thread>
#include <chrono>
#include <filesystem>
#include <openssl/evp.h>

namespace security_agent {
namespace monitoring {

// FileInfo sınıfı implementasyonu
nlohmann::json FileInfo::toJson() const {
    nlohmann::json json;
    json["path"] = path;
    json["name"] = name;
    json["extension"] = extension;
    json["size"] = size;
    json["last_modified"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        last_modified.time_since_epoch()).count();
    json["hash"] = hash;
    json["owner"] = owner;
    json["permissions"] = permissions;
    json["is_directory"] = is_directory;
    json["is_symlink"] = is_symlink;
    
    if (is_symlink && target_path) {
        json["target_path"] = *target_path;
    }
    
    return json;
}

// FileEvent sınıfı implementasyonu
nlohmann::json FileEvent::toJson() const {
    nlohmann::json json;
    
    // Olay tipini string'e dönüştür
    std::string type_str;
    switch (type) {
        case FileEventType::CREATED: type_str = "CREATED"; break;
        case FileEventType::MODIFIED: type_str = "MODIFIED"; break;
        case FileEventType::DELETED: type_str = "DELETED"; break;
        case FileEventType::RENAMED: type_str = "RENAMED"; break;
        case FileEventType::PERMISSION_CHANGED: type_str = "PERMISSION_CHANGED"; break;
        case FileEventType::OWNER_CHANGED: type_str = "OWNER_CHANGED"; break;
        case FileEventType::ACCESSED: type_str = "ACCESSED"; break;
        case FileEventType::MOVED: type_str = "MOVED"; break;
        case FileEventType::OTHER: type_str = "OTHER"; break;
    }
    json["type"] = type_str;
    
    json["file"] = file.toJson();
    json["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    
    if (changes) {
        nlohmann::json changes_json;
        changes_json["content_changed"] = changes->content_changed;
        changes_json["size_changed"] = changes->size_changed;
        changes_json["permissions_changed"] = changes->permissions_changed;
        changes_json["owner_changed"] = changes->owner_changed;
        
        if (changes->old_size) {
            changes_json["old_size"] = *changes->old_size;
        }
        
        if (changes->new_size) {
            changes_json["new_size"] = *changes->new_size;
        }
        
        if (changes->old_permissions) {
            changes_json["old_permissions"] = *changes->old_permissions;
        }
        
        if (changes->new_permissions) {
            changes_json["new_permissions"] = *changes->new_permissions;
        }
        
        if (changes->old_owner) {
            changes_json["old_owner"] = *changes->old_owner;
        }
        
        if (changes->new_owner) {
            changes_json["new_owner"] = *changes->new_owner;
        }
        
        json["changes"] = changes_json;
    }
    
    if (old_path) {
        json["old_path"] = *old_path;
    }
    
    return json;
}

// FileMonitoring sınıfı implementasyonu
FileMonitoring::FileMonitoring(
    const std::string& config_path,
    std::shared_ptr<event_management::EventManager> event_manager,
    std::shared_ptr<logging::LoggingModule> logging_module,
    std::shared_ptr<routing::RoutingModule> routing_module,
    std::shared_ptr<detection::DetectionModule> detection_module
) : MonitoringInterface(config_path, event_manager, logging_module, routing_module, detection_module),
    monitoring_(false) {
    
    loadConfig();
}

FileMonitoring::~FileMonitoring() {
    stopMonitoring();
}

void FileMonitoring::monitor() {
    if (!config_.enabled) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::INFO,
                "FileMonitoring",
                "monitor",
                "Dosya izleme devre dışı",
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
        return;
    }
    
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::INFO,
            "FileMonitoring",
            "monitor",
            "Dosya izleme başlatılıyor",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
    }
    
    startMonitoring();
}

void FileMonitoring::loadConfig() {
    try {
        YAML::Node config = YAML::LoadFile(config_path_);
        auto file_monitoring_config = config["monitoring_module"]["file_monitoring"];
        
        // Temel yapılandırma
        config_.enabled = file_monitoring_config["enabled"] ? 
            file_monitoring_config["enabled"].as<bool>() : true;
        
        // Tarama aralığı
        config_.scan_interval = file_monitoring_config["scan_interval"] ? 
            file_monitoring_config["scan_interval"].as<int>() : 5000;
        
        // İzlenecek dizinler
        config_.monitored_directories.clear();
        if (file_monitoring_config["monitored_directories"]) {
            for (const auto& dir_node : file_monitoring_config["monitored_directories"]) {
                MonitoredDirectory dir;
                dir.path = dir_node["path"].as<std::string>();
                dir.recursive = dir_node["recursive"] ? dir_node["recursive"].as<bool>() : true;
                
                if (dir_node["extensions"]) {
                    for (const auto& ext : dir_node["extensions"]) {
                        dir.extensions.push_back(ext.as<std::string>());
                    }
                }
                
                config_.monitored_directories.push_back(dir);
            }
        }
        
        // İzlenecek dosyalar
        config_.monitored_files.clear();
        if (file_monitoring_config["monitored_files"]) {
            for (const auto& file : file_monitoring_config["monitored_files"]) {
                config_.monitored_files.push_back(file.as<std::string>());
            }
        }
        
        // Hariç tutulan dizinler
        config_.excluded_directories.clear();
        if (file_monitoring_config["excluded_directories"]) {
            for (const auto& dir : file_monitoring_config["excluded_directories"]) {
                config_.excluded_directories.push_back(dir.as<std::string>());
            }
        }
        
        // Hariç tutulan dosyalar
        config_.excluded_files.clear();
        if (file_monitoring_config["excluded_files"]) {
            for (const auto& file : file_monitoring_config["excluded_files"]) {
                config_.excluded_files.push_back(file.as<std::string>());
            }
        }
        
        // Önbellek boyutu
        config_.cache_size = file_monitoring_config["cache_size"] ? 
            file_monitoring_config["cache_size"].as<int>() : 1000;
        
        // Şüpheli uzantılar
        config_.suspicious_extensions.clear();
        if (file_monitoring_config["suspicious_extensions"]) {
            for (const auto& ext : file_monitoring_config["suspicious_extensions"]) {
                config_.suspicious_extensions.push_back(ext.as<std::string>());
            }
        } else {
            // Varsayılan şüpheli uzantılar
            config_.suspicious_extensions = {
                ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".sh"
            };
        }
        
        // Maksimum dosya boyutu
        config_.max_file_size = file_monitoring_config["max_file_size"] ? 
            file_monitoring_config["max_file_size"].as<uint64_t>() : 10 * 1024 * 1024;
        
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::INFO,
                "FileMonitoring",
                "loadConfig",
                "Dosya izleme yapılandırması yüklendi",
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
                "FileMonitoring",
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

void FileMonitoring::startMonitoring() {
    if (monitoring_) {
        return;
    }
    
    monitoring_ = true;
    
    // İzleme iş parçacığını başlat
    monitoring_thread_ = std::thread([this]() {
        while (monitoring_) {
            // İzlenecek dizinleri tara
            for (const auto& dir : config_.monitored_directories) {
                scanDirectory(dir);
            }
            
            // İzlenecek dosyaları tara
            for (const auto& file_path : config_.monitored_files) {
                scanFile(file_path);
            }
            
            // İzleme aralığı kadar bekle
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.scan_interval));
        }
    });
}

void FileMonitoring::stopMonitoring() {
    if (!monitoring_) {
        return;
    }
    
    monitoring_ = false;
    
    if (monitoring_thread_.joinable()) {
        monitoring_thread_.join();
    }
    
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::INFO,
            "FileMonitoring",
            "stopMonitoring",
            "Dosya izleme durduruldu",
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            std::nullopt
        );
    }
}

void FileMonitoring::scanDirectory(const MonitoredDirectory& dir) {
    try {
        std::filesystem::path dir_path(dir.path);
        
        if (!std::filesystem::exists(dir_path)) {
            if (logging_module_) {
                logging_module_->log(
                    logging::LogLevel::WARNING,
                    "FileMonitoring",
                    "scanDirectory",
                    "Dizin bulunamadı: " + dir.path,
                    __FILE__,
                    __FUNCTION__,
                    std::to_string(__LINE__),
                    std::nullopt
                );
            }
            return;
        }
        
        if (!std::filesystem::is_directory(dir_path)) {
            if (logging_module_) {
                logging_module_->log(
                    logging::LogLevel::WARNING,
                    "FileMonitoring",
                    "scanDirectory",
                    "Belirtilen yol bir dizin değil: " + dir.path,
                    __FILE__,
                    __FUNCTION__,
                    std::to_string(__LINE__),
                    std::nullopt
                );
            }
            return;
        }
        
        // Dizini tara
        if (dir.recursive) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(dir_path)) {
                if (shouldScanFile(entry.path().string(), dir.extensions)) {
                    scanFile(entry.path().string());
                }
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
                if (shouldScanFile(entry.path().string(), dir.extensions)) {
                    scanFile(entry.path().string());
                }
            }
        }
    } catch (const std::exception& e) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::ERROR,
                "FileMonitoring",
                "scanDirectory",
                "Dizin taranırken hata oluştu: " + std::string(e.what()),
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
    }
}

bool FileMonitoring::shouldScanFile(const std::string& file_path, const std::vector<std::string>& extensions) {
    // Dosya mı kontrol et
    std::filesystem::path path(file_path);
    if (!std::filesystem::is_regular_file(path)) {
        return false;
    }
    
    // Hariç tutulan dizinleri kontrol et
    for (const auto& excluded_dir : config_.excluded_directories) {
        std::filesystem::path excluded_path(excluded_dir);
        if (std::filesystem::path(file_path).string().find(excluded_path.string()) == 0) {
            return false;
        }
    }
    
    // Hariç tutulan dosyaları kontrol et
    for (const auto& excluded_file : config_.excluded_files) {
        if (file_path == excluded_file) {
            return false;
        }
    }
    
    // Uzantıları kontrol et
    if (!extensions.empty()) {
        std::string extension = path.extension().string();
        bool extension_found = false;
        
        for (const auto& ext : extensions) {
            if (extension == ext) {
                extension_found = true;
                break;
            }
        }
        
        if (!extension_found) {
            return false;
        }
    }
    
    return true;
}

void FileMonitoring::scanFile(const std::string& file_path) {
    try {
        std::filesystem::path path(file_path);
        
        if (!std::filesystem::exists(path)) {
            // Dosya silinmiş, silme olayı oluştur
            handleDeletedFile(file_path);
            return;
        }
        
        if (!std::filesystem::is_regular_file(path)) {
            return;
        }
        
        // Dosya bilgilerini al
        FileInfo file_info = getFileInfo(file_path);
        
        // Dosya önbellekte var mı kontrol et
        bool file_changed = false;
        {
            std::lock_guard<std::mutex> lock(file_mutex_);
            auto it = file_cache_.find(file_path);
            
            if (it != file_cache_.end()) {
                // Dosya var, değişmiş mi kontrol et
                file_changed = detectFileChanges(it->second, file_info);
                
                // Dosya bilgilerini güncelle
                it->second = file_info;
            } else {
                // Dosya yok, ekle
                file_cache_[file_path] = file_info;
                
                // Yeni dosya olayı oluştur
                handleNewFile(file_info);
            }
        }
        
        // Dosya değişmişse, değişiklik olayı oluştur
        if (file_changed) {
            handleModifiedFile(file_info);
        }
    } catch (const std::exception& e) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::ERROR,
                "FileMonitoring",
                "scanFile",
                "Dosya taranırken hata oluştu: " + std::string(e.what()),
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
    }
}

FileInfo FileMonitoring::getFileInfo(const std::string& file_path) {
    FileInfo info;
    std::filesystem::path path(file_path);
    
    info.path = file_path;
    info.name = path.filename().string();
    info.extension = path.extension().string();
    
    auto file_status = std::filesystem::status(path);
    auto last_write_time = std::filesystem::last_write_time(path);
    
    info.size = std::filesystem::file_size(path);
    info.last_modified = std::chrono::system_clock::now();
    
    // Dosya hash'ini hesapla
    if (info.size <= config_.max_file_size) {
        info.hash = calculateFileHash(file_path);
    } else {
        info.hash = "file_too_large";
    }
    
    // Dosya sahibi ve izinleri
    info.owner = "unknown"; // Platform bağımlı
    info.permissions = static_cast<int>(file_status.permissions());
    
    info.is_directory = std::filesystem::is_directory(path);
    info.is_symlink = std::filesystem::is_symlink(path);
    
    if (info.is_symlink) {
        info.target_path = std::filesystem::read_symlink(path).string();
    }
    
    return info;
}

std::string FileMonitoring::calculateFileHash(const std::string& file_path) {
    try {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            return "file_not_accessible";
        }
        
        // EVP_Digest kullanarak hash hesapla
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            return "hash_error";
        }
        
        const EVP_MD* md = EVP_sha256();
        if (!md) {
            EVP_MD_CTX_free(mdctx);
            return "hash_error";
        }
        
        if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
            EVP_MD_CTX_free(mdctx);
            return "hash_error";
        }
        
        const size_t buffer_size = 8192;
        char buffer[buffer_size];
        
        while (file.good()) {
            file.read(buffer, buffer_size);
            size_t bytes_read = file.gcount();
            
            if (bytes_read > 0) {
                if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return "hash_error";
                }
            }
        }
        
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;
        
        if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
            EVP_MD_CTX_free(mdctx);
            return "hash_error";
        }
        
        EVP_MD_CTX_free(mdctx);
        
        // Hash'i hexadecimal string'e dönüştür
        std::stringstream ss;
        for (unsigned int i = 0; i < hash_len; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        
        return ss.str();
    } catch (const std::exception& e) {
        if (logging_module_) {
            logging_module_->log(
                logging::LogLevel::ERROR,
                "FileMonitoring",
                "calculateFileHash",
                "Dosya hash'i hesaplanırken hata oluştu: " + std::string(e.what()),
                __FILE__,
                __FUNCTION__,
                std::to_string(__LINE__),
                std::nullopt
            );
        }
        return "hash_error";
    }
}

bool FileMonitoring::detectFileChanges(const FileInfo& old_info, const FileInfo& new_info) {
    // Dosya boyutu değişmiş mi
    if (old_info.size != new_info.size) {
        return true;
    }
    
    // Dosya hash'i değişmiş mi
    if (old_info.hash != new_info.hash) {
        return true;
    }
    
    // Dosya izinleri değişmiş mi
    if (old_info.permissions != new_info.permissions) {
        return true;
    }
    
    // Dosya sahibi değişmiş mi
    if (old_info.owner != new_info.owner) {
        return true;
    }
    
    return false;
}

void FileMonitoring::handleNewFile(const FileInfo& file_info) {
    FileEvent event;
    event.type = FileEventType::CREATED;
    event.file = file_info;
    event.timestamp = std::chrono::system_clock::now();
    
    // Olayı kaydet
    {
        std::lock_guard<std::mutex> lock(file_mutex_);
        file_events_.push_back(event);
        
        // Olay sayısını sınırla
        if (file_events_.size() > config_.cache_size) {
            file_events_.erase(file_events_.begin());
        }
    }
    
    // Olayı detection modülüne gönder
    if (detection_module_) {
        detection_module_->detectThreats(event.toJson());
    }
    
    // Olayı log'a yaz
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::INFO,
            "FileMonitoring",
            "handleNewFile",
            "Yeni dosya oluşturuldu: " + file_info.path,
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            event.toJson()
        );
    }
    
    // Şüpheli uzantı kontrolü
    for (const auto& ext : config_.suspicious_extensions) {
        if (file_info.extension == ext) {
            if (logging_module_) {
                logging_module_->log(
                    logging::LogLevel::WARNING,
                    "FileMonitoring",
                    "handleNewFile",
                    "Şüpheli uzantılı dosya oluşturuldu: " + file_info.path,
                    __FILE__,
                    __FUNCTION__,
                    std::to_string(__LINE__),
                    event.toJson()
                );
            }
            break;
        }
    }
}

void FileMonitoring::handleModifiedFile(const FileInfo& file_info) {
    FileEvent event;
    event.type = FileEventType::MODIFIED;
    event.file = file_info;
    event.timestamp = std::chrono::system_clock::now();
    
    // Değişiklik bilgilerini ekle
    FileChanges changes;
    changes.content_changed = true;
    changes.size_changed = true;
    changes.new_size = file_info.size;
    event.changes = changes;
    
    // Olayı kaydet
    {
        std::lock_guard<std::mutex> lock(file_mutex_);
        file_events_.push_back(event);
        
        // Olay sayısını sınırla
        if (file_events_.size() > config_.cache_size) {
            file_events_.erase(file_events_.begin());
        }
    }
    
    // Olayı detection modülüne gönder
    if (detection_module_) {
        detection_module_->detectThreats(event.toJson());
    }
    
    // Olayı log'a yaz
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::INFO,
            "FileMonitoring",
            "handleModifiedFile",
            "Dosya değiştirildi: " + file_info.path,
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            event.toJson()
        );
    }
}

void FileMonitoring::handleDeletedFile(const std::string& file_path) {
    // Dosya önbellekte var mı kontrol et
    FileInfo file_info;
    bool file_found = false;
    
    {
        std::lock_guard<std::mutex> lock(file_mutex_);
        auto it = file_cache_.find(file_path);
        
        if (it != file_cache_.end()) {
            file_info = it->second;
            file_cache_.erase(it);
            file_found = true;
        }
    }
    
    if (!file_found) {
        return;
    }
    
    FileEvent event;
    event.type = FileEventType::DELETED;
    event.file = file_info;
    event.timestamp = std::chrono::system_clock::now();
    
    // Olayı kaydet
    {
        std::lock_guard<std::mutex> lock(file_mutex_);
        file_events_.push_back(event);
        
        // Olay sayısını sınırla
        if (file_events_.size() > config_.cache_size) {
            file_events_.erase(file_events_.begin());
        }
    }
    
    // Olayı detection modülüne gönder
    if (detection_module_) {
        detection_module_->detectThreats(event.toJson());
    }
    
    // Olayı log'a yaz
    if (logging_module_) {
        logging_module_->log(
            logging::LogLevel::INFO,
            "FileMonitoring",
            "handleDeletedFile",
            "Dosya silindi: " + file_path,
            __FILE__,
            __FUNCTION__,
            std::to_string(__LINE__),
            event.toJson()
        );
    }
}

std::vector<FileEvent> FileMonitoring::getFileEvents(int limit) const {
    std::lock_guard<std::mutex> lock(file_mutex_);
    
    if (limit <= 0 || limit >= static_cast<int>(file_events_.size())) {
        return file_events_;
    }
    
    return std::vector<FileEvent>(
        file_events_.end() - limit,
        file_events_.end()
    );
}

std::vector<FileInfo> FileMonitoring::getMonitoredFiles() const {
    std::lock_guard<std::mutex> lock(file_mutex_);
    
    std::vector<FileInfo> files;
    for (const auto& pair : file_cache_) {
        files.push_back(pair.second);
    }
    
    return files;
}

} // namespace monitoring
} // namespace security_agent 