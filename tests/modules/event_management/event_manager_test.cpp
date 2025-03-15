#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "modules/event_management/event_manager.hpp"
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/tcp_socket.h>
#include <nlohmann/json.hpp>

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::StrEq;

namespace security_agent {
namespace event_management {

class MockRabbitMQ : public RabbitMQInterface {
public:
    MOCK_METHOD(amqp_connection_state_t, amqp_new_connection, (), (override));
    MOCK_METHOD(amqp_socket_t*, amqp_tcp_socket_new, (amqp_connection_state_t), (override));
    MOCK_METHOD(int, amqp_socket_open, (amqp_socket_t*, const char*, int), (override));
    MOCK_METHOD(amqp_rpc_reply_t, amqp_login, (amqp_connection_state_t, const char*, int, int, int, amqp_sasl_method_enum, const char*, const char*), (override));
    MOCK_METHOD(amqp_channel_open_ok_t*, amqp_channel_open, (amqp_connection_state_t, amqp_channel_t), (override));
    MOCK_METHOD(amqp_rpc_reply_t, amqp_get_rpc_reply, (amqp_connection_state_t), (override));
    MOCK_METHOD(amqp_rpc_reply_t, amqp_channel_close, (amqp_connection_state_t, amqp_channel_t, int), (override));
    MOCK_METHOD(amqp_rpc_reply_t, amqp_connection_close, (amqp_connection_state_t, int), (override));
    MOCK_METHOD(int, amqp_destroy_connection, (amqp_connection_state_t), (override));
    MOCK_METHOD(amqp_exchange_declare_ok_t*, amqp_exchange_declare, (amqp_connection_state_t, amqp_channel_t, amqp_bytes_t, amqp_bytes_t, amqp_boolean_t, amqp_boolean_t, amqp_boolean_t, amqp_boolean_t, amqp_table_t), (override));
    MOCK_METHOD(amqp_queue_declare_ok_t*, amqp_queue_declare, (amqp_connection_state_t, amqp_channel_t, amqp_bytes_t, amqp_boolean_t, amqp_boolean_t, amqp_boolean_t, amqp_boolean_t, amqp_table_t), (override));
    MOCK_METHOD(amqp_queue_bind_ok_t*, amqp_queue_bind, (amqp_connection_state_t, amqp_channel_t, amqp_bytes_t, amqp_bytes_t, amqp_bytes_t, amqp_table_t), (override));
};

class EventManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        mock_rabbitmq = std::make_shared<MockRabbitMQ>();
        
        amqp_connection_state_t conn = (amqp_connection_state_t)1;
        amqp_socket_t* socket = (amqp_socket_t*)2;
        amqp_rpc_reply_t reply = {AMQP_RESPONSE_NORMAL, {AMQP_REPLY_SUCCESS}};
        amqp_channel_open_ok_t channel_ok;

        EXPECT_CALL(*mock_rabbitmq, amqp_new_connection())
            .WillOnce(Return(conn));

        EXPECT_CALL(*mock_rabbitmq, amqp_tcp_socket_new(conn))
            .WillOnce(Return(socket));

        EXPECT_CALL(*mock_rabbitmq, amqp_socket_open(socket, _, 5672))
            .WillOnce(Return(0));

        EXPECT_CALL(*mock_rabbitmq, amqp_login(conn, _, _, _, _, AMQP_SASL_METHOD_PLAIN, _, _))
            .WillOnce(Return(reply));

        EXPECT_CALL(*mock_rabbitmq, amqp_channel_open(conn, 1))
            .WillOnce(Return(&channel_ok));

        EXPECT_CALL(*mock_rabbitmq, amqp_get_rpc_reply(conn))
            .WillOnce(Return(reply));

        manager = std::make_unique<EventManager>("localhost", 5672, "guest", "guest", "/", false, mock_rabbitmq);
    }

    void TearDown() override {
        manager.reset();
    }

    std::unique_ptr<EventManager> manager;
    std::shared_ptr<MockRabbitMQ> mock_rabbitmq;
};

TEST_F(EventManagerTest, PublishEvent) {
    Event event(EventType::MALWARE_DETECTED, "test_module", SeverityLevel::CRITICAL, nlohmann::json{{"test_key", "test_value"}});
    amqp_rpc_reply_t reply = {AMQP_RESPONSE_NORMAL, {AMQP_REPLY_SUCCESS}};
    amqp_exchange_declare_ok_t declare_ok;

    EXPECT_CALL(*mock_rabbitmq, amqp_exchange_declare(_, _, _, _, _, _, _, _, _))
        .WillOnce(Return(&declare_ok));

    EXPECT_CALL(*mock_rabbitmq, amqp_get_rpc_reply(_))
        .WillOnce(Return(reply));

    EXPECT_NO_THROW(manager->publishEvent(event, "test_exchange", "test_routing_key"));
}

TEST_F(EventManagerTest, Subscribe) {
    auto callback = [](const Event& event) {};
    amqp_rpc_reply_t reply = {AMQP_RESPONSE_NORMAL, {AMQP_REPLY_SUCCESS}};
    amqp_queue_declare_ok_t declare_ok;
    amqp_queue_bind_ok_t bind_ok;

    EXPECT_CALL(*mock_rabbitmq, amqp_queue_declare(_, _, _, _, _, _, _, _))
        .WillOnce(Return(&declare_ok));

    EXPECT_CALL(*mock_rabbitmq, amqp_queue_bind(_, _, _, _, _, _))
        .WillOnce(Return(&bind_ok));

    EXPECT_NO_THROW(manager->subscribe("test_queue", "test_exchange", "test_routing_key", callback));
}

TEST_F(EventManagerTest, Unsubscribe) {
    amqp_rpc_reply_t reply = {AMQP_RESPONSE_NORMAL, {AMQP_REPLY_SUCCESS}};
    amqp_queue_declare_ok_t declare_ok;

    EXPECT_CALL(*mock_rabbitmq, amqp_queue_declare(_, _, _, _, _, _, _, _))
        .WillOnce(Return(&declare_ok));

    EXPECT_NO_THROW(manager->unsubscribe("test_queue"));
}

TEST_F(EventManagerTest, DeclareExchange) {
    amqp_rpc_reply_t reply = {AMQP_RESPONSE_NORMAL, {AMQP_REPLY_SUCCESS}};
    amqp_exchange_declare_ok_t declare_ok;

    EXPECT_CALL(*mock_rabbitmq, amqp_exchange_declare(_, _, _, _, _, _, _, _, _))
        .WillOnce(Return(&declare_ok));

    EXPECT_CALL(*mock_rabbitmq, amqp_get_rpc_reply(_))
        .WillOnce(Return(reply));

    EXPECT_NO_THROW(manager->declareExchange("test_exchange", "direct"));
}

} // namespace event_management
} // namespace security_agent