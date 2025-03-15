#include "modules/monitoring/network_monitoring.hpp"
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

class NetworkMonitoringTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test için geçici dizin oluştur
        test_dir_ = std::filesystem::temp_directory_path() / "network_monitoring_test";
        std::filesystem::create_directories(test_dir_);
        
        // Test için geçici config dosyası oluştur
        config_path_ = test_dir_ / "test_config.yaml";
        std::ofstream config_file(config_path_);
        config_file << R"(
monitoring_module:
  network_monitoring:
    enabled: true
    interfaces:
      - eth0
      - lo
    capture_timeout: 500
    packet_buffer_size: 1024
    protocols:
      - tcp
      - udp
      - icmp
    ports:
      - 22
      - 80
      - 443
    excluded_ips:
      - 127.0.0.1
      - 192.168.1.1
    pcap_file: /tmp/network_capture.pcap
    max_capture_size: 1048576
)";
        config_file.close();
        
        // Mock nesneleri oluştur
        event_manager_ = std::make_shared<testing::NiceMock<MockEventManager>>();
        logging_module_ = std::make_shared<testing::NiceMock<MockLoggingModule>>();
        routing_module_ = std::make_shared<testing::NiceMock<MockRoutingModule>>();
        detection_module_ = std::make_shared<testing::NiceMock<MockDetectionModule>>();
        
        // NetworkMonitoring nesnesini oluştur
        network_monitoring_ = std::make_unique<NetworkMonitoring>(
            config_path_.string(),
            event_manager_,
            logging_module_,
            routing_module_,
            detection_module_
        );
    }
    
    void TearDown() override {
        network_monitoring_.reset();
        std::filesystem::remove_all(test_dir_);
    }
    
    std::filesystem::path test_dir_;
    std::filesystem::path config_path_;
    std::shared_ptr<testing::NiceMock<MockEventManager>> event_manager_;
    std::shared_ptr<testing::NiceMock<MockLoggingModule>> logging_module_;
    std::shared_ptr<testing::NiceMock<MockRoutingModule>> routing_module_;
    std::shared_ptr<testing::NiceMock<MockDetectionModule>> detection_module_;
    std::unique_ptr<NetworkMonitoring> network_monitoring_;
};

TEST_F(NetworkMonitoringTest, LoadConfigTest) {
    // Yapılandırma yükleme işlemini test et
    EXPECT_NO_THROW(network_monitoring_->loadConfig());
    
    // Yapılandırma değerlerini kontrol et
    auto interfaces = network_monitoring_->getInterfaces();
    EXPECT_EQ(interfaces.size(), 2);
    EXPECT_TRUE(std::find(interfaces.begin(), interfaces.end(), "eth0") != interfaces.end());
    EXPECT_TRUE(std::find(interfaces.begin(), interfaces.end(), "lo") != interfaces.end());
}

TEST_F(NetworkMonitoringTest, StartStopMonitoringTest) {
    // İzleme başlatma ve durdurma işlemlerini test et
    EXPECT_NO_THROW(network_monitoring_->monitor());
    EXPECT_NO_THROW(network_monitoring_->stop());
}

TEST_F(NetworkMonitoringTest, PacketCaptureTest) {
    // Test için sahte paket verisi oluştur
    std::vector<uint8_t> packet_data = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0x3c,
        0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01, 0x04, 0xd2, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
        0xbd, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    // Paket işleme fonksiyonunu test et
    EXPECT_NO_THROW(network_monitoring_->processPacket(packet_data));
}

TEST_F(NetworkMonitoringTest, FilterPacketTest) {
    // Test için sahte paket verisi oluştur (TCP, port 80)
    std::vector<uint8_t> tcp_packet = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0x3c,
        0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01, 0x04, 0xd2, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
        0xbd, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    // Paket filtreleme fonksiyonunu test et
    EXPECT_TRUE(network_monitoring_->shouldCapturePacket(tcp_packet));
    
    // Hariç tutulan IP için test
    std::vector<uint8_t> excluded_ip_packet = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0x3c,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x04, 0xd2, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
        0xbd, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    EXPECT_FALSE(network_monitoring_->shouldCapturePacket(excluded_ip_packet));
}

TEST_F(NetworkMonitoringTest, SavePacketToPcapTest) {
    // Test için sahte paket verisi oluştur
    std::vector<uint8_t> packet_data = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0x3c,
        0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01, 0x04, 0xd2, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
        0xbd, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    // PCAP dosyasına kaydetme fonksiyonunu test et
    EXPECT_NO_THROW(network_monitoring_->savePacketToPcap(packet_data));
}

TEST_F(NetworkMonitoringTest, DetectAnomalyTest) {
    // Test için sahte paket verisi oluştur
    std::vector<uint8_t> packet_data = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0x3c,
        0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01, 0x04, 0xd2, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
        0xbd, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    // Anomali tespiti fonksiyonunu test et
    EXPECT_NO_THROW(network_monitoring_->detectAnomaly(packet_data));
}

} // namespace test
} // namespace monitoring
} // namespace security_agent

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 