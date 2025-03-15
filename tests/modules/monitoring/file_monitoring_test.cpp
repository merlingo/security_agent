#include "modules/monitoring/file_monitoring.hpp"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <vector>

namespace security_agent {
namespace monitoring {
namespace test {

// Mock sınıfları
class MockEventManager : public event_management::EventManager {
public:
    MockEventManager() : EventManager("localhost", 5672, "guest", "guest", "/", false) {}
    
    MOCK_METHOD(void, publishEvent, (const event_management::Event& event,
                                    const std::string& exchange,
                                    const std::string& routing_key,
                                    bool mandatory,
                                    uint8_t priority), (override));
};

class MockLoggingModule : public logging::LoggingModule {
public:
    MockLoggingModule() : LoggingModule("test_config.yaml") {}
    
    MOCK_METHOD(void, log, (logging::LogLevel level,
                           const std::string& module,
                           const std::string& function,
                           const std::string& message,
                           const std::string& file,
                           const std::string& func,
                           const std::string& line,
                           const std::optional<nlohmann::json>& data), (override));
};

class MockRoutingModule : public routing::RoutingModule {
public:
    MockRoutingModule() : RoutingModule("test_config.yaml") {}
    
    MOCK_METHOD(routing::SendResult, sendData, (const nlohmann::json& data, const std::string& index_name), (override));
};

class MockDetectionModule : public detection::DetectionModule {
public:
    MockDetectionModule() : DetectionModule("test_config.yaml") {}
    
    MOCK_METHOD(void, detectThreats, (const nlohmann::json& data), (override));
};

class FileMonitoringTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test için geçici dizin oluştur
        test_dir_ = std::filesystem::temp_directory_path() / "file_monitoring_test";
        std::filesystem::create_directories(test_dir_);
        
        // Test için geçici config dosyası oluştur
        config_path_ = test_dir_ / "test_config.yaml";
        std::ofstream config_file(config_path_);
        config_file << R"(
monitoring_module:
  file_monitoring:
    enabled: true
    scan_interval: 60
    monitored_directories:
      - path: /etc
        recursive: true
        extensions:
          - .conf
          - .ini
      - path: /var/log
        recursive: false
        extensions:
          - .log
    excluded_directories:
      - /tmp
      - /proc
    excluded_files:
      - .DS_Store
      - Thumbs.db
    file_hash_cache_size: 1000
    suspicious_extensions:
      - .exe
      - .dll
      - .sh
    max_file_size: 10485760
)";
        config_file.close();
        
        // Test için geçici dosyalar oluştur
        test_files_dir_ = test_dir_ / "files";
        std::filesystem::create_directories(test_files_dir_);
        
        // Normal dosya
        normal_file_path_ = test_files_dir_ / "normal.txt";
        std::ofstream normal_file(normal_file_path_);
        normal_file << "Bu normal bir dosyadır.";
        normal_file.close();
        
        // Şüpheli dosya
        suspicious_file_path_ = test_files_dir_ / "suspicious.exe";
        std::ofstream suspicious_file(suspicious_file_path_);
        suspicious_file << "Bu şüpheli bir dosyadır.";
        suspicious_file.close();
        
        // Mock nesneleri oluştur
        event_manager_ = std::make_shared<testing::NiceMock<MockEventManager>>();
        logging_module_ = std::make_shared<testing::NiceMock<MockLoggingModule>>();
        routing_module_ = std::make_shared<testing::NiceMock<MockRoutingModule>>();
        detection_module_ = std::make_shared<testing::NiceMock<MockDetectionModule>>();
        
        // FileMonitoring nesnesini oluştur
        file_monitoring_ = std::make_unique<FileMonitoring>(
            config_path_.string(),
            event_manager_,
            logging_module_,
            routing_module_,
            detection_module_
        );
    }
    
    void TearDown() override {
        file_monitoring_.reset();
        std::filesystem::remove_all(test_dir_);
    }
    
    std::filesystem::path test_dir_;
    std::filesystem::path test_files_dir_;
    std::filesystem::path config_path_;
    std::filesystem::path normal_file_path_;
    std::filesystem::path suspicious_file_path_;
    std::shared_ptr<testing::NiceMock<MockEventManager>> event_manager_;
    std::shared_ptr<testing::NiceMock<MockLoggingModule>> logging_module_;
    std::shared_ptr<testing::NiceMock<MockRoutingModule>> routing_module_;
    std::shared_ptr<testing::NiceMock<MockDetectionModule>> detection_module_;
    std::unique_ptr<FileMonitoring> file_monitoring_;
};

TEST_F(FileMonitoringTest, LoadConfigTest) {
    // Yapılandırma yükleme işlemini test et
    EXPECT_NO_THROW(file_monitoring_->loadConfig());
    
    // Yapılandırma değerlerini kontrol et
    auto monitored_dirs = file_monitoring_->getMonitoredDirectories();
    EXPECT_EQ(monitored_dirs.size(), 2);
    EXPECT_TRUE(std::find_if(monitored_dirs.begin(), monitored_dirs.end(),
                           [](const auto& d) { return d.path == "/etc"; }) != monitored_dirs.end());
}

TEST_F(FileMonitoringTest, StartStopMonitoringTest) {
    // İzleme başlatma ve durdurma işlemlerini test et
    EXPECT_NO_THROW(file_monitoring_->monitor());
    EXPECT_NO_THROW(file_monitoring_->stop());
}

TEST_F(FileMonitoringTest, ScanDirectoryTest) {
    // Dizin tarama işlemini test et
    auto files = file_monitoring_->scanDirectory(test_files_dir_.string(), true);
    EXPECT_EQ(files.size(), 2);
    EXPECT_TRUE(std::find_if(files.begin(), files.end(),
                           [this](const auto& f) { return f.path == normal_file_path_.string(); }) != files.end());
    EXPECT_TRUE(std::find_if(files.begin(), files.end(),
                           [this](const auto& f) { return f.path == suspicious_file_path_.string(); }) != files.end());
}

TEST_F(FileMonitoringTest, FileInfoToJsonTest) {
    // Dosya bilgisini JSON'a dönüştürme işlemini test et
    FileInfo file;
    file.path = normal_file_path_.string();
    file.size = std::filesystem::file_size(normal_file_path_);
    file.last_modified = std::filesystem::last_write_time(normal_file_path_);
    file.hash = "abcdef1234567890";
    file.owner = "testuser";
    file.permissions = "rw-r--r--";
    
    auto json = file_monitoring_->fileInfoToJson(file);
    EXPECT_EQ(json["path"], normal_file_path_.string());
    EXPECT_EQ(json["size"], std::filesystem::file_size(normal_file_path_));
    EXPECT_TRUE(json.contains("last_modified"));
    EXPECT_EQ(json["hash"], "abcdef1234567890");
    EXPECT_EQ(json["owner"], "testuser");
    EXPECT_EQ(json["permissions"], "rw-r--r--");
}

TEST_F(FileMonitoringTest, CalculateFileHashTest) {
    // Dosya hash hesaplama işlemini test et
    std::string hash = file_monitoring_->calculateFileHash(normal_file_path_.string());
    EXPECT_FALSE(hash.empty());
}

TEST_F(FileMonitoringTest, DetectFileChangeTest) {
    // Dosya değişikliği tespiti işlemini test et
    FileInfo old_file;
    old_file.path = normal_file_path_.string();
    old_file.size = 10;
    old_file.last_modified = std::filesystem::file_time_type::clock::now() - std::chrono::hours(1);
    old_file.hash = "old_hash";
    
    FileInfo new_file;
    new_file.path = normal_file_path_.string();
    new_file.size = std::filesystem::file_size(normal_file_path_);
    new_file.last_modified = std::filesystem::last_write_time(normal_file_path_);
    new_file.hash = "new_hash";
    
    auto changes = file_monitoring_->detectFileChanges(old_file, new_file);
    EXPECT_TRUE(changes.size_changed);
    EXPECT_TRUE(changes.content_changed);
    EXPECT_TRUE(changes.time_changed);
}

TEST_F(FileMonitoringTest, IsSuspiciousFileTest) {
    // Şüpheli dosya tespiti işlemini test et
    FileInfo suspicious_file;
    suspicious_file.path = suspicious_file_path_.string();
    suspicious_file.extension = ".exe";
    
    EXPECT_TRUE(file_monitoring_->isSuspiciousFile(suspicious_file));
    
    // Normal dosya tespiti işlemini test et
    FileInfo normal_file;
    normal_file.path = normal_file_path_.string();
    normal_file.extension = ".txt";
    
    EXPECT_FALSE(file_monitoring_->isSuspiciousFile(normal_file));
}

TEST_F(FileMonitoringTest, IsExcludedFileTest) {
    // Hariç tutulan dosya tespiti işlemini test et
    FileInfo excluded_file;
    excluded_file.path = "/tmp/excluded.txt";
    
    EXPECT_TRUE(file_monitoring_->isExcludedFile(excluded_file));
    
    // Dahil edilen dosya tespiti işlemini test et
    FileInfo included_file;
    included_file.path = "/etc/config.conf";
    
    EXPECT_FALSE(file_monitoring_->isExcludedFile(included_file));
}

TEST_F(FileMonitoringTest, HandleFileEventTest) {
    // Dosya olayı işleme işlemini test et
    FileEvent event;
    event.type = FileEventType::MODIFIED;
    event.file.path = normal_file_path_.string();
    event.file.size = std::filesystem::file_size(normal_file_path_);
    event.file.last_modified = std::filesystem::last_write_time(normal_file_path_);
    event.file.hash = "abcdef1234567890";
    event.file.owner = "testuser";
    event.file.permissions = "rw-r--r--";
    event.timestamp = std::chrono::system_clock::now();
    
    EXPECT_NO_THROW(file_monitoring_->handleFileEvent(event));
}

} // namespace test
} // namespace monitoring
} // namespace security_agent

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 