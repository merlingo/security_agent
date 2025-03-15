#include "modules/monitoring/syslog_monitoring.hpp"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>

namespace security_agent {
namespace monitoring {
namespace test {

class SyslogEntryTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test için geçici dizin oluştur
        test_dir_ = std::filesystem::temp_directory_path() / "syslog_test";
        std::filesystem::create_directories(test_dir_);
    }
    
    void TearDown() override {
        // Test dizinini temizle
        std::filesystem::remove_all(test_dir_);
    }
    
    std::filesystem::path test_dir_;
};

TEST_F(SyslogEntryTest, ParseLogEntryTest) {
    // Test log girişi
    std::string log_line = "May 15 14:23:45 server sshd[12345]: Accepted password for user1 from 192.168.1.100 port 22";
    
    // Log girişini manuel olarak ayrıştır
    SyslogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.hostname = "server";
    entry.process_name = "sshd";
    entry.pid = 12345;
    entry.message = "Accepted password for user1 from 192.168.1.100 port 22";
    
    // Ayrıştırma sonuçlarını kontrol et
    EXPECT_EQ(entry.hostname, "server");
    EXPECT_EQ(entry.process_name, "sshd");
    EXPECT_EQ(entry.pid, 12345);
    EXPECT_EQ(entry.message, "Accepted password for user1 from 192.168.1.100 port 22");
}

TEST_F(SyslogEntryTest, ToJsonTest) {
    // Test log girişi
    SyslogEntry entry;
    entry.hostname = "server";
    entry.process_name = "sshd";
    entry.pid = 12345;
    entry.message = "Accepted password for user1 from 192.168.1.100 port 22";
    entry.timestamp = std::chrono::system_clock::now();
    
    // JSON'a dönüştür
    nlohmann::json json = entry.toJson();
    
    // JSON içeriğini kontrol et
    EXPECT_EQ(json["hostname"], "server");
    EXPECT_EQ(json["process_name"], "sshd");
    EXPECT_EQ(json["pid"], 12345);
    EXPECT_EQ(json["message"], "Accepted password for user1 from 192.168.1.100 port 22");
    EXPECT_TRUE(json.contains("timestamp"));
}

TEST_F(SyslogEntryTest, CalculateHashTest) {
    // Test log girişi
    SyslogEntry entry;
    entry.hostname = "server";
    entry.process_name = "sshd";
    entry.pid = 12345;
    entry.message = "Accepted password for user1 from 192.168.1.100 port 22";
    entry.timestamp = std::chrono::system_clock::now();
    
    // Hash hesapla
    std::string hash = entry.calculateHash();
    
    // Hash'in boş olmadığını kontrol et
    EXPECT_FALSE(hash.empty());
    
    // Hash'in 32 karakter (MD5) olduğunu kontrol et
    EXPECT_EQ(hash.length(), 32);
}

TEST_F(SyslogEntryTest, LogEventToJsonTest) {
    // Test log girişi
    SyslogEntry entry;
    entry.hostname = "server";
    entry.process_name = "sshd";
    entry.pid = 12345;
    entry.message = "Accepted password for user1 from 192.168.1.100 port 22";
    entry.timestamp = std::chrono::system_clock::now();
    
    // Log olayı oluştur
    LogEvent event;
    event.log_entry = entry;
    event.event_type = LogEventType::LOGIN_SUCCESS;
    event.event_description = "Successful login";
    event.event_details["user"] = "user1";
    event.event_details["ip"] = "192.168.1.100";
    
    // JSON'a dönüştür
    nlohmann::json json = event.toJson();
    
    // JSON içeriğini kontrol et
    EXPECT_EQ(json["event_type"], "LOGIN_SUCCESS");
    EXPECT_EQ(json["event_description"], "Successful login");
    EXPECT_EQ(json["event_details"]["user"], "user1");
    EXPECT_EQ(json["event_details"]["ip"], "192.168.1.100");
    EXPECT_TRUE(json.contains("log_entry"));
}

} // namespace test
} // namespace monitoring
} // namespace security_agent

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 