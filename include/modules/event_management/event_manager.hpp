#pragma once

#include "event.hpp"
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/tcp_socket.h>
#include <rabbitmq-c/ssl_socket.h>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <thread>

namespace security_agent {
namespace event_management {

using EventCallback = std::function<void(const Event&)>;

// RabbitMQ fonksiyonları için interface
class RabbitMQInterface {
public:
    virtual ~RabbitMQInterface() = default;
    virtual amqp_connection_state_t amqp_new_connection() = 0;
    virtual amqp_socket_t* amqp_tcp_socket_new(amqp_connection_state_t state) = 0;
    virtual int amqp_socket_open(amqp_socket_t* socket, const char* host, int port) = 0;
    virtual amqp_rpc_reply_t amqp_login(amqp_connection_state_t state, const char* vhost, int channel_max, int frame_max, int heartbeat, amqp_sasl_method_enum sasl_method, const char* username, const char* password) = 0;
    virtual amqp_channel_open_ok_t* amqp_channel_open(amqp_connection_state_t state, amqp_channel_t channel) = 0;
    virtual amqp_rpc_reply_t amqp_get_rpc_reply(amqp_connection_state_t state) = 0;
    virtual amqp_rpc_reply_t amqp_channel_close(amqp_connection_state_t state, amqp_channel_t channel, int code) = 0;
    virtual amqp_rpc_reply_t amqp_connection_close(amqp_connection_state_t state, int code) = 0;
    virtual int amqp_destroy_connection(amqp_connection_state_t state) = 0;
    virtual amqp_exchange_declare_ok_t* amqp_exchange_declare(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t exchange, amqp_bytes_t type, amqp_boolean_t passive, amqp_boolean_t durable, amqp_boolean_t auto_delete, amqp_boolean_t internal, amqp_table_t arguments) = 0;
    virtual amqp_queue_declare_ok_t* amqp_queue_declare(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_boolean_t passive, amqp_boolean_t durable, amqp_boolean_t exclusive, amqp_boolean_t auto_delete, amqp_table_t arguments) = 0;
    virtual amqp_queue_bind_ok_t* amqp_queue_bind(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_bytes_t exchange, amqp_bytes_t routing_key, amqp_table_t arguments) = 0;
};

// Gerçek RabbitMQ implementasyonu
class RealRabbitMQ : public RabbitMQInterface {
public:
    amqp_connection_state_t amqp_new_connection() override { return ::amqp_new_connection(); }
    amqp_socket_t* amqp_tcp_socket_new(amqp_connection_state_t state) override { return ::amqp_tcp_socket_new(state); }
    int amqp_socket_open(amqp_socket_t* socket, const char* host, int port) override { return ::amqp_socket_open(socket, host, port); }
    amqp_rpc_reply_t amqp_login(amqp_connection_state_t state, const char* vhost, int channel_max, int frame_max, int heartbeat, amqp_sasl_method_enum sasl_method, const char* username, const char* password) override { return ::amqp_login(state, vhost, channel_max, frame_max, heartbeat, sasl_method, username, password); }
    amqp_channel_open_ok_t* amqp_channel_open(amqp_connection_state_t state, amqp_channel_t channel) override { return ::amqp_channel_open(state, channel); }
    amqp_rpc_reply_t amqp_get_rpc_reply(amqp_connection_state_t state) override { return ::amqp_get_rpc_reply(state); }
    amqp_rpc_reply_t amqp_channel_close(amqp_connection_state_t state, amqp_channel_t channel, int code) override { return ::amqp_channel_close(state, channel, code); }
    amqp_rpc_reply_t amqp_connection_close(amqp_connection_state_t state, int code) override { return ::amqp_connection_close(state, code); }
    int amqp_destroy_connection(amqp_connection_state_t state) override { return ::amqp_destroy_connection(state); }
    amqp_exchange_declare_ok_t* amqp_exchange_declare(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t exchange, amqp_bytes_t type, amqp_boolean_t passive, amqp_boolean_t durable, amqp_boolean_t auto_delete, amqp_boolean_t internal, amqp_table_t arguments) override { return ::amqp_exchange_declare(state, channel, exchange, type, passive, durable, auto_delete, internal, arguments); }
    amqp_queue_declare_ok_t* amqp_queue_declare(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_boolean_t passive, amqp_boolean_t durable, amqp_boolean_t exclusive, amqp_boolean_t auto_delete, amqp_table_t arguments) override { return ::amqp_queue_declare(state, channel, queue, passive, durable, exclusive, auto_delete, arguments); }
    amqp_queue_bind_ok_t* amqp_queue_bind(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_bytes_t exchange, amqp_bytes_t routing_key, amqp_table_t arguments) override { return ::amqp_queue_bind(state, channel, queue, exchange, routing_key, arguments); }
};

class EventManager {
public:
    EventManager(const std::string& host,
                int port,
                const std::string& username,
                const std::string& password,
                const std::string& vhost,
                bool use_ssl,
                std::shared_ptr<RabbitMQInterface> rabbitmq = std::make_shared<RealRabbitMQ>());
    
    virtual ~EventManager();
    
    // Event yayınlama
    virtual void publishEvent(const Event& event,
                             const std::string& exchange,
                             const std::string& routing_key,
                             bool mandatory = false,
                             uint8_t priority = 0);
    
    // Event dinleme
    virtual void subscribe(const std::string& queue,
                          const std::string& exchange,
                          const std::string& binding_key,
                          const std::function<void(const Event&)>& callback);
    
    // Bağlantı yönetimi
    void unsubscribe(const std::string& queue);
    
    // Exchange management
    void declareExchange(const std::string& exchange, const std::string& type = "topic");
    
    // Dead Letter Queue setup
    void setupDeadLetterQueue(const std::string& queue);
    
    // Start/Stop processing
    void start();
    void stop();

protected:
    // RabbitMQ bağlantı yönetimi
    virtual void setupConnection();
    void closeConnection();
    void processMessage(const std::string& consumer_tag, const amqp_envelope_t* envelope);

private:
    std::string host_;
    int port_;
    std::string username_;
    std::string password_;
    std::string vhost_;
    bool use_ssl_;

    amqp_connection_state_t conn_;
    std::unordered_map<std::string, std::function<void(const Event&)>> callbacks_;
    std::mutex mutex_;
    bool running_;
    std::string secret_key_; // For message signing
    std::unique_ptr<std::thread> consumer_thread_;
    std::shared_ptr<RabbitMQInterface> rabbitmq_;
    
    void setupSSL();
    void retryDelivery(const Event& event,
                       const std::string& exchange,
                       const std::string& routing_key,
                       int attempt = 0);
    void checkRpcReply(amqp_rpc_reply_t reply, const std::string& context);
    void consumerLoop();
};

} // namespace event_management
} // namespace security_agent 