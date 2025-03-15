#include "modules/monitoring/process_monitoring.hpp"
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

class ProcessMonitoringTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test için geçici dizin oluştur
        test_dir_ = std::filesystem::temp_directory_path() / "process_monitoring_test";
        std::filesystem::create_directories(test_dir_);
        
        // Test için geçici config dosyası oluştur
        config_path_ = test_dir_ / "test_config.yaml";
        std::ofstream config_file(config_path_);
        config_file << R"(
monitoring_module:
  process_monitoring:
    enabled: true
    scan_interval: 10
    process_history_size: 100
    suspicious_processes:
      - name: malware.exe
        hash: abcdef1234567890
      - name: backdoor.exe
        hash: 0987654321fedcba
    excluded_processes:
      - name: system
      - name: svchost.exe
    cpu_threshold: 90
    memory_threshold: 85
    network_threshold: 1048576
    disk_threshold: 5242880
)";
        config_file.close();
        
        // Mock nesneleri oluştur
        event_manager_ = std::make_shared<testing::NiceMock<MockEventManager>>();
        logging_module_ = std::make_shared<testing::NiceMock<MockLoggingModule>>();
        routing_module_ = std::make_shared<testing::NiceMock<MockRoutingModule>>();
        detection_module_ = std::make_shared<testing::NiceMock<MockDetectionModule>>();
        
        // ProcessMonitoring nesnesini oluştur
        process_monitoring_ = std::make_unique<ProcessMonitoring>(
            config_path_.string(),
            event_manager_,
            logging_module_,
            routing_module_,
            detection_module_
        );
    }
    
    void TearDown() override {
        process_monitoring_.reset();
        std::filesystem::remove_all(test_dir_);
    }
    
    std::filesystem::path test_dir_;
    std::filesystem::path config_path_;
    std::shared_ptr<testing::NiceMock<MockEventManager>> event_manager_;
    std::shared_ptr<testing::NiceMock<MockLoggingModule>> logging_module_;
    std::shared_ptr<testing::NiceMock<MockRoutingModule>> routing_module_;
    std::shared_ptr<testing::NiceMock<MockDetectionModule>> detection_module_;
    std::unique_ptr<ProcessMonitoring> process_monitoring_;
};

TEST_F(ProcessMonitoringTest, LoadConfigTest) {
    // Yapılandırma yükleme işlemini test et
    EXPECT_NO_THROW(process_monitoring_->loadConfig());
    
    // Yapılandırma değerlerini kontrol et
    auto suspicious_processes = process_monitoring_->getSuspiciousProcesses();
    EXPECT_EQ(suspicious_processes.size(), 2);
    EXPECT_TRUE(std::find_if(suspicious_processes.begin(), suspicious_processes.end(),
                           [](const auto& p) { return p.name == "malware.exe"; }) != suspicious_processes.end());
}

TEST_F(ProcessMonitoringTest, StartStopMonitoringTest) {
    // İzleme başlatma ve durdurma işlemlerini test et
    EXPECT_NO_THROW(process_monitoring_->monitor());
    EXPECT_NO_THROW(process_monitoring_->stop());
}

TEST_F(ProcessMonitoringTest, GetRunningProcessesTest) {
    // Çalışan süreçleri alma işlemini test et
    auto processes = process_monitoring_->getRunningProcesses();
    EXPECT_FALSE(processes.empty());
}

TEST_F(ProcessMonitoringTest, ProcessInfoToJsonTest) {
    // Süreç bilgisini JSON'a dönüştürme işlemini test et
    ProcessInfo process;
    process.pid = 1234;
    process.name = "test_process";
    process.user = "testuser";
    process.cpu_usage = 10.5;
    process.memory_usage = 1024 * 1024;
    process.start_time = std::chrono::system_clock::now();
    process.command_line = "/usr/bin/test_process --arg1 --arg2";
    
    auto json = process_monitoring_->processInfoToJson(process);
    EXPECT_EQ(json["pid"], 1234);
    EXPECT_EQ(json["name"], "test_process");
    EXPECT_EQ(json["user"], "testuser");
    EXPECT_EQ(json["cpu_usage"], 10.5);
    EXPECT_EQ(json["memory_usage"], 1024 * 1024);
    EXPECT_TRUE(json.contains("start_time"));
    EXPECT_EQ(json["command_line"], "/usr/bin/test_process --arg1 --arg2");
}

TEST_F(ProcessMonitoringTest, DetectSuspiciousProcessTest) {
    // Şüpheli süreç tespiti işlemini test et
    ProcessInfo suspicious_process;
    suspicious_process.pid = 1234;
    suspicious_process.name = "malware.exe";
    suspicious_process.user = "testuser";
    suspicious_process.cpu_usage = 10.5;
    suspicious_process.memory_usage = 1024 * 1024;
    suspicious_process.start_time = std::chrono::system_clock::now();
    suspicious_process.command_line = "/usr/bin/malware.exe --arg1 --arg2";
    
    EXPECT_TRUE(process_monitoring_->isSuspiciousProcess(suspicious_process));
    
    // Normal süreç tespiti işlemini test et
    ProcessInfo normal_process;
    normal_process.pid = 5678;
    normal_process.name = "normal.exe";
    normal_process.user = "testuser";
    normal_process.cpu_usage = 5.0;
    normal_process.memory_usage = 512 * 1024;
    normal_process.start_time = std::chrono::system_clock::now();
    normal_process.command_line = "/usr/bin/normal.exe --arg1 --arg2";
    
    EXPECT_FALSE(process_monitoring_->isSuspiciousProcess(normal_process));
}

TEST_F(ProcessMonitoringTest, DetectAnomalousResourceUsageTest) {
    // Anormal kaynak kullanımı tespiti işlemini test et
    ProcessInfo high_cpu_process;
    high_cpu_process.pid = 1234;
    high_cpu_process.name = "high_cpu.exe";
    high_cpu_process.user = "testuser";
    high_cpu_process.cpu_usage = 95.0;  // Yüksek CPU kullanımı
    high_cpu_process.memory_usage = 512 * 1024;
    high_cpu_process.start_time = std::chrono::system_clock::now();
    high_cpu_process.command_line = "/usr/bin/high_cpu.exe";
    
    EXPECT_TRUE(process_monitoring_->hasAnomalousResourceUsage(high_cpu_process));
    
    // Normal kaynak kullanımı tespiti işlemini test et
    ProcessInfo normal_process;
    normal_process.pid = 5678;
    normal_process.name = "normal.exe";
    normal_process.user = "testuser";
    normal_process.cpu_usage = 5.0;
    normal_process.memory_usage = 512 * 1024;
    normal_process.start_time = std::chrono::system_clock::now();
    normal_process.command_line = "/usr/bin/normal.exe";
    
    EXPECT_FALSE(process_monitoring_->hasAnomalousResourceUsage(normal_process));
}

TEST_F(ProcessMonitoringTest, CalculateProcessHashTest) {
    // Süreç hash hesaplama işlemini test et
    ProcessInfo process;
    process.pid = 1234;
    process.name = "test_process";
    process.user = "testuser";
    process.command_line = "/usr/bin/test_process --arg1 --arg2";
    process.executable_path = "/usr/bin/test_process";
    
    std::string hash = process_monitoring_->calculateProcessHash(process);
    EXPECT_FALSE(hash.empty());
}

} // namespace test
} // namespace monitoring
} // namespace security_agent

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 