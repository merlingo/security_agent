#include "modules/routing/routing_module.hpp"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <fstream>
#include <thread>
#include <chrono>
#include <filesystem>

namespace security_agent {
namespace routing {
namespace test {

class RoutingModuleTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test dizini oluştur
        test_dir_ = std::filesystem::temp_directory_path() / "routing_test";
        std::filesystem::create_directories(test_dir_);
        
        // Test yapılandırma dosyası oluştur
        config_path_ = test_dir_ / "routing_config.yaml";
        createTestConfig();
        
        // Test çıktı dosyası
        output_file_ = test_dir_ / "test_output.json";
    }
    
    void TearDown() override {
        // Test dizinini temizle
        std::filesystem::remove_all(test_dir_);
    }
    
    void createTestConfig() {
        std::ofstream config_file(config_path_);
        config_file << "routing_module:\n";
        config_file << "  enabled: true\n";
        config_file << "  retry_count: 3\n";
        config_file << "  retry_delay_seconds: 1\n";
        config_file << "  queue_size_limit: 100\n";
        config_file << "  batch_size: 10\n";
        config_file << "  processing_interval_seconds: 1\n";
        config_file << "  server:\n";
        config_file << "    host: localhost\n";
        config_file << "    port: 9200\n";
        config_file << "    username: test\n";
        config_file << "    password: test\n";
        config_file << "    use_ssl: false\n";
        config_file << "  destinations:\n";
        config_file << "    elasticsearch: elasticsearch\n";
        config_file << "    file: file\n";
        config_file << "  indices:\n";
        config_file << "    security_events:\n";
        config_file << "      destination_type: file\n";
        config_file << "      destination_url: " << (test_dir_ / "security_events.json").string() << "\n";
        config_file << "      use_timestamp: true\n";
        config_file << "      timestamp_field: timestamp\n";
        config_file << "    network_traffic:\n";
        config_file << "      destination_type: file\n";
        config_file << "      destination_url: " << (test_dir_ / "network_traffic.json").string() << "\n";
        config_file << "      use_timestamp: true\n";
        config_file << "      timestamp_field: timestamp\n";
        config_file.close();
    }
    
    std::filesystem::path test_dir_;
    std::filesystem::path config_path_;
    std::filesystem::path output_file_;
};

TEST_F(RoutingModuleTest, InitializationTest) {
    // Modülü oluştur
    RoutingModule module(config_path_);
    
    // İndekslerin yapılandırıldığını kontrol et
    EXPECT_TRUE(module.isIndexConfigured("security_events"));
    EXPECT_TRUE(module.isIndexConfigured("network_traffic"));
    EXPECT_FALSE(module.isIndexConfigured("nonexistent_index"));
}

TEST_F(RoutingModuleTest, SendDataToFileTest) {
    // Modülü oluştur
    RoutingModule module(config_path_);
    
    // Test verisi oluştur
    nlohmann::json data;
    data["message"] = "Test message";
    data["severity"] = "info";
    data["source"] = "test";
    
    // Veriyi gönder
    SendResult result = module.sendData(data, "security_events");
    
    // Sonucu kontrol et
    EXPECT_EQ(result, SendResult::SUCCESS);
    
    // Dosyanın oluşturulduğunu kontrol etmek için biraz bekle
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Dosyanın oluşturulduğunu kontrol et
    EXPECT_TRUE(std::filesystem::exists(test_dir_ / "security_events.json"));
    
    // Dosya içeriğini kontrol et
    std::ifstream file(test_dir_ / "security_events.json");
    std::string content;
    std::getline(file, content);
    file.close();
    
    // JSON içeriğini kontrol et
    nlohmann::json parsed_json = nlohmann::json::parse(content);
    EXPECT_EQ(parsed_json["message"], "Test message");
    EXPECT_EQ(parsed_json["severity"], "info");
    EXPECT_EQ(parsed_json["source"], "test");
    EXPECT_TRUE(parsed_json.contains("timestamp"));
}

TEST_F(RoutingModuleTest, InvalidIndexTest) {
    // Modülü oluştur
    RoutingModule module(config_path_);
    
    // Test verisi oluştur
    nlohmann::json data;
    data["message"] = "Test message";
    
    // Geçersiz indekse veri göndermeyi dene
    SendResult result = module.sendData(data, "nonexistent_index");
    
    // Sonucu kontrol et
    EXPECT_EQ(result, SendResult::INVALID_DATA);
}

TEST_F(RoutingModuleTest, EmptyDataTest) {
    // Modülü oluştur
    RoutingModule module(config_path_);
    
    // Boş veri oluştur
    nlohmann::json data;
    
    // Boş veriyi göndermeyi dene
    SendResult result = module.sendData(data, "security_events");
    
    // Sonucu kontrol et
    EXPECT_EQ(result, SendResult::INVALID_DATA);
}

TEST_F(RoutingModuleTest, ReloadConfigTest) {
    // Modülü oluştur
    RoutingModule module(config_path_);
    
    // Yapılandırmayı değiştir
    std::ofstream config_file(config_path_);
    config_file << "routing_module:\n";
    config_file << "  enabled: true\n";
    config_file << "  retry_count: 3\n";
    config_file << "  retry_delay_seconds: 1\n";
    config_file << "  queue_size_limit: 100\n";
    config_file << "  batch_size: 10\n";
    config_file << "  processing_interval_seconds: 1\n";
    config_file << "  server:\n";
    config_file << "    host: localhost\n";
    config_file << "    port: 9200\n";
    config_file << "  indices:\n";
    config_file << "    new_index:\n";
    config_file << "      destination_type: file\n";
    config_file << "      destination_url: " << (test_dir_ / "new_index.json").string() << "\n";
    config_file.close();
    
    // Yapılandırmayı yeniden yükle
    module.reloadConfig();
    
    // Yeni indeksin yapılandırıldığını kontrol et
    EXPECT_TRUE(module.isIndexConfigured("new_index"));
    
    // Eski indekslerin artık yapılandırılmadığını kontrol et
    EXPECT_FALSE(module.isIndexConfigured("security_events"));
    EXPECT_FALSE(module.isIndexConfigured("network_traffic"));
}

} // namespace test
} // namespace routing
} // namespace security_agent

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 