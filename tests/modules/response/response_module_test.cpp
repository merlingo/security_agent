#include "modules/response/response_module.hpp"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <fstream>
#include <filesystem>

using namespace testing;
using namespace security_agent::response;

// RabbitMQ mock sınıfı
class MockRabbitMQ : public security_agent::event_management::RabbitMQInterface {
public:
    MOCK_METHOD(amqp_connection_state_t, amqp_new_connection, (), (override));
    MOCK_METHOD(amqp_socket_t*, amqp_tcp_socket_new, (amqp_connection_state_t state), (override));
    MOCK_METHOD(int, amqp_socket_open, (amqp_socket_t* socket, const char* host, int port), (override));
    MOCK_METHOD(amqp_rpc_reply_t, amqp_login, (amqp_connection_state_t state, const char* vhost, int channel_max, int frame_max, int heartbeat, amqp_sasl_method_enum sasl_method, const char* username, const char* password), (override));
    MOCK_METHOD(amqp_channel_open_ok_t*, amqp_channel_open, (amqp_connection_state_t state, amqp_channel_t channel), (override));
    MOCK_METHOD(amqp_rpc_reply_t, amqp_get_rpc_reply, (amqp_connection_state_t state), (override));
    MOCK_METHOD(amqp_rpc_reply_t, amqp_channel_close, (amqp_connection_state_t state, amqp_channel_t channel, int code), (override));
    MOCK_METHOD(amqp_rpc_reply_t, amqp_connection_close, (amqp_connection_state_t state, int code), (override));
    MOCK_METHOD(int, amqp_destroy_connection, (amqp_connection_state_t state), (override));
    MOCK_METHOD(amqp_exchange_declare_ok_t*, amqp_exchange_declare, (amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t exchange, amqp_bytes_t type, amqp_boolean_t passive, amqp_boolean_t durable, amqp_boolean_t auto_delete, amqp_boolean_t internal, amqp_table_t arguments), (override));
    MOCK_METHOD(amqp_queue_declare_ok_t*, amqp_queue_declare, (amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_boolean_t passive, amqp_boolean_t durable, amqp_boolean_t exclusive, amqp_boolean_t auto_delete, amqp_table_t arguments), (override));
    MOCK_METHOD(amqp_queue_bind_ok_t*, amqp_queue_bind, (amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_bytes_t exchange, amqp_bytes_t routing_key, amqp_table_t arguments), (override));
};

// EventManager mock sınıfı
class MockEventManager : public security_agent::event_management::EventManager {
public:
    MockEventManager(std::shared_ptr<MockRabbitMQ> rabbitmq) : EventManager("", 0, "", "", "", false, rabbitmq) {}
    MOCK_METHOD(void, publishEvent, (const security_agent::event_management::Event& event,
                                   const std::string& exchange,
                                   const std::string& routing_key,
                                   bool mandatory,
                                   uint8_t priority), (override));
    MOCK_METHOD(void, subscribe, (const std::string& queue,
                                const std::string& exchange,
                                const std::string& binding_key,
                                const std::function<void(const security_agent::event_management::Event&)>& callback), (override));
protected:
    void setupConnection() override {} // Boş implementasyon
};

class ResponseModuleTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test için geçici config dosyası oluştur
        std::ofstream config_file("test_config.yaml");
        config_file << R"(
response_module:
  enabled: true
  log_level: debug
  quarantine_folder: /tmp/quarantine
  rabbitmq:
    host: localhost
    port: 5672
    queue: response_queue
  actions:
    kill_process: true
    quarantine: true
    erase_file: true
    transfer_file: true
    reboot: true
)";
        config_file.close();

        // Quarantine klasörünü oluştur
        std::filesystem::create_directories("/tmp/quarantine");

        // Mock RabbitMQ'yu oluştur
        auto mock_rabbitmq = std::make_shared<MockRabbitMQ>();

        // Mock RabbitMQ fonksiyonları için beklentileri ayarla
        amqp_connection_state_t fake_conn = (amqp_connection_state_t)1;
        amqp_socket_t* fake_socket = (amqp_socket_t*)1;
        amqp_rpc_reply_t fake_reply = {AMQP_RESPONSE_NORMAL};
        amqp_channel_open_ok_t fake_channel = {};

        EXPECT_CALL(*mock_rabbitmq, amqp_new_connection())
            .WillOnce(Return(fake_conn));
        EXPECT_CALL(*mock_rabbitmq, amqp_tcp_socket_new(fake_conn))
            .WillOnce(Return(fake_socket));
        EXPECT_CALL(*mock_rabbitmq, amqp_socket_open(fake_socket, _, _))
            .WillOnce(Return(0));
        EXPECT_CALL(*mock_rabbitmq, amqp_login(fake_conn, _, _, _, _, _, _, _))
            .WillOnce(Return(fake_reply));
        EXPECT_CALL(*mock_rabbitmq, amqp_channel_open(fake_conn, _))
            .WillOnce(Return(&fake_channel));
        EXPECT_CALL(*mock_rabbitmq, amqp_get_rpc_reply(fake_conn))
            .WillRepeatedly(Return(fake_reply));

        // Mock EventManager'ı oluştur
        mock_event_manager_ = std::make_shared<MockEventManager>(mock_rabbitmq);

        // ResponseModule'ü oluşturmadan önce mock_event_manager_'ı ayarla
        module_ = std::make_unique<ResponseModule>("test_config.yaml");
        module_->setEventManager(mock_event_manager_);
    }

    void TearDown() override {
        module_.reset();
        std::filesystem::remove_all("/tmp/quarantine");
        std::filesystem::remove("test_config.yaml");
    }

    std::unique_ptr<ResponseModule> module_;
    std::shared_ptr<MockEventManager> mock_event_manager_;
};

TEST_F(ResponseModuleTest, KillProcess) {
    // Test için sahte bir PID kullan
    int test_pid = 12345;
    
    // Event gönderilmesini bekle
    EXPECT_CALL(*mock_event_manager_, publishEvent(_, _, _, _, _))
        .Times(1);
    
    // Process sonlandırma işlemini test et
    EXPECT_TRUE(module_->killProcess(test_pid));
}

TEST_F(ResponseModuleTest, QuarantineFile) {
    // Test için geçici bir dosya oluştur
    std::string test_file = "/tmp/test_file.txt";
    std::ofstream file(test_file);
    file << "test content";
    file.close();

    // Event gönderilmesini bekle
    EXPECT_CALL(*mock_event_manager_, publishEvent(_, _, _, _, _))
        .Times(1);

    // Dosyayı karantinaya al
    EXPECT_TRUE(module_->quarantineFile(test_file));

    // Dosyanın karantina klasörüne taşındığını kontrol et
    EXPECT_TRUE(std::filesystem::exists("/tmp/quarantine/test_file.txt"));
    EXPECT_FALSE(std::filesystem::exists(test_file));
}

TEST_F(ResponseModuleTest, EraseFile) {
    // Test için geçici bir dosya oluştur
    std::string test_file = "/tmp/test_file.txt";
    std::ofstream file(test_file);
    file << "test content";
    file.close();

    // Event gönderilmesini bekle
    EXPECT_CALL(*mock_event_manager_, publishEvent(_, _, _, _, _))
        .Times(1);

    // Dosyayı sil
    EXPECT_TRUE(module_->eraseFile(test_file));

    // Dosyanın silindiğini kontrol et
    EXPECT_FALSE(std::filesystem::exists(test_file));
}

TEST_F(ResponseModuleTest, TransferFile) {
    // Test için geçici bir kaynak dosyası oluştur
    std::string source_file = "/tmp/source_file.txt";
    std::string dest_file = "/tmp/dest/transferred_file.txt";
    
    std::ofstream file(source_file);
    file << "test content";
    file.close();

    // Event gönderilmesini bekle
    EXPECT_CALL(*mock_event_manager_, publishEvent(_, _, _, _, _))
        .Times(1);

    // Transfer işlemini gerçekleştir
    EXPECT_TRUE(module_->transferFile(source_file, dest_file));

    // Dosyanın başarıyla transfer edildiğini kontrol et
    EXPECT_TRUE(std::filesystem::exists(dest_file));
    
    // Temizlik
    std::filesystem::remove(source_file);
    std::filesystem::remove_all("/tmp/dest");
}

TEST_F(ResponseModuleTest, StartStop) {
    // Subscribe çağrısını bekle
    EXPECT_CALL(*mock_event_manager_, subscribe(_, _, _, _))
        .Times(1);

    // Module'ü başlat
    module_->start();

    // Module'ü durdur
    module_->stop();
}

TEST_F(ResponseModuleTest, Reboot) {
    // Event gönderilmesini bekle
    EXPECT_CALL(*mock_event_manager_, publishEvent(_, _, _, _, _))
        .Times(1);

    // Reboot işlemi sistem seviyesinde olduğu için test edilemez
    // Sadece fonksiyonun çağrılabildiğini kontrol et
    EXPECT_TRUE(module_->reboot());
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 