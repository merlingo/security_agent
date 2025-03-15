#include "modules/event_management/event_manager.hpp"
#include <stdexcept>
#include <chrono>
#include <thread>
#include <sstream>

namespace security_agent {
namespace event_management {

EventManager::EventManager(const std::string& host,
                         int port,
                         const std::string& username,
                         const std::string& password,
                         const std::string& vhost,
                         bool use_ssl,
                         std::shared_ptr<RabbitMQInterface> rabbitmq)
    : host_(host),
      port_(port),
      username_(username),
      password_(password),
      vhost_(vhost),
      use_ssl_(use_ssl),
      conn_(nullptr),
      running_(false),
      rabbitmq_(rabbitmq) {
    setupConnection();
}

EventManager::~EventManager() {
    stop();
    closeConnection();
}

void EventManager::setupConnection() {
    conn_ = rabbitmq_->amqp_new_connection();
    if (!conn_) {
        throw std::runtime_error("Failed to create AMQP connection");
    }

    amqp_socket_t* socket;
    if (use_ssl_) {
        setupSSL();
    } else {
        socket = rabbitmq_->amqp_tcp_socket_new(conn_);
        if (!socket) {
            throw std::runtime_error("Failed to create TCP socket");
        }
    }

    int status = rabbitmq_->amqp_socket_open(socket, host_.c_str(), port_);
    if (status < 0) {
        throw std::runtime_error("Failed to open socket");
    }

    amqp_rpc_reply_t reply = rabbitmq_->amqp_login(conn_, vhost_.c_str(),
                                                  0, 131072, 0, AMQP_SASL_METHOD_PLAIN,
                                                  username_.c_str(), password_.c_str());
    checkRpcReply(reply, "Login");

    amqp_channel_open_ok_t* channel_ok = rabbitmq_->amqp_channel_open(conn_, 1);
    if (!channel_ok) {
        throw std::runtime_error("Failed to open channel");
    }
    checkRpcReply(rabbitmq_->amqp_get_rpc_reply(conn_), "Channel open");
}

void EventManager::closeConnection() {
    if (conn_) {
        rabbitmq_->amqp_channel_close(conn_, 1, AMQP_REPLY_SUCCESS);
        rabbitmq_->amqp_connection_close(conn_, AMQP_REPLY_SUCCESS);
        rabbitmq_->amqp_destroy_connection(conn_);
        conn_ = nullptr;
    }
}

void EventManager::publishEvent(const Event& event,
                              const std::string& exchange,
                              const std::string& routing_key,
                              bool mandatory,
                              uint8_t priority) {
    // Exchange'i deklare et
    amqp_bytes_t exchange_name = amqp_cstring_bytes(exchange.c_str());
    amqp_bytes_t exchange_type = amqp_cstring_bytes("topic");
    amqp_table_t arguments = amqp_empty_table;

    amqp_exchange_declare_ok_t* declare_ok = rabbitmq_->amqp_exchange_declare(
        conn_, 1, exchange_name, exchange_type,
        0, 1, 0, 0, arguments);
    if (!declare_ok) {
        throw std::runtime_error("Failed to declare exchange");
    }
    checkRpcReply(rabbitmq_->amqp_get_rpc_reply(conn_), "Exchange declare");

    // TODO: Event'i serialize et ve publish et
}

void EventManager::subscribe(const std::string& queue,
                           const std::string& exchange,
                           const std::string& binding_key,
                           const std::function<void(const Event&)>& callback) {
    // Queue'yu deklare et
    amqp_bytes_t queue_name = amqp_cstring_bytes(queue.c_str());
    amqp_table_t arguments = amqp_empty_table;

    amqp_queue_declare_ok_t* declare_ok = rabbitmq_->amqp_queue_declare(
        conn_, 1, queue_name,
        0, 0, 0, 0, arguments);
    if (!declare_ok) {
        throw std::runtime_error("Failed to declare queue");
    }

    // Queue'yu exchange'e bağla
    amqp_bytes_t exchange_name = amqp_cstring_bytes(exchange.c_str());
    amqp_bytes_t binding_key_name = amqp_cstring_bytes(binding_key.c_str());

    amqp_queue_bind_ok_t* bind_ok = rabbitmq_->amqp_queue_bind(
        conn_, 1, queue_name, exchange_name,
        binding_key_name, amqp_empty_table);
    if (!bind_ok) {
        throw std::runtime_error("Failed to bind queue");
    }

    // Callback'i kaydet
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_[queue] = callback;
}

void EventManager::unsubscribe(const std::string& queue) {
    // Queue'yu deklare et (passive = true)
    amqp_bytes_t queue_name = amqp_cstring_bytes(queue.c_str());
    amqp_table_t arguments = amqp_empty_table;

    amqp_queue_declare_ok_t* declare_ok = rabbitmq_->amqp_queue_declare(
        conn_, 1, queue_name,
        1, 0, 0, 0, arguments);
    if (!declare_ok) {
        throw std::runtime_error("Failed to declare queue");
    }

    // Callback'i kaldır
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.erase(queue);
}

void EventManager::declareExchange(const std::string& exchange, const std::string& type) {
    amqp_bytes_t exchange_name = amqp_cstring_bytes(exchange.c_str());
    amqp_bytes_t exchange_type = amqp_cstring_bytes(type.c_str());
    amqp_table_t arguments = amqp_empty_table;

    amqp_exchange_declare_ok_t* declare_ok = rabbitmq_->amqp_exchange_declare(
        conn_, 1, exchange_name, exchange_type,
        0, 1, 0, 0, arguments);
    if (!declare_ok) {
        throw std::runtime_error("Failed to declare exchange");
    }
    checkRpcReply(rabbitmq_->amqp_get_rpc_reply(conn_), "Exchange declare");
}

void EventManager::checkRpcReply(amqp_rpc_reply_t reply, const std::string& context) {
    switch (reply.reply_type) {
        case AMQP_RESPONSE_NORMAL:
            return;
        case AMQP_RESPONSE_NONE:
            throw std::runtime_error(context + ": missing RPC reply type");
        case AMQP_RESPONSE_LIBRARY_EXCEPTION:
            throw std::runtime_error(context + ": " + amqp_error_string2(reply.library_error));
        case AMQP_RESPONSE_SERVER_EXCEPTION:
            throw std::runtime_error(context + ": server exception");
    }
}

void EventManager::setupSSL() {
    // TODO: SSL bağlantı kurulumu
}

void EventManager::start() {
    running_ = true;
    consumer_thread_ = std::make_unique<std::thread>(&EventManager::consumerLoop, this);
}

void EventManager::stop() {
    running_ = false;
    if (consumer_thread_ && consumer_thread_->joinable()) {
        consumer_thread_->join();
    }
}

void EventManager::consumerLoop() {
    // TODO: Consumer loop implementasyonu
}

void EventManager::retryDelivery(const Event& event,
                               const std::string& exchange,
                               const std::string& routing_key,
                               int attempt) {
    // TODO: Retry delivery implementasyonu
}

void EventManager::setupDeadLetterQueue(const std::string& queue) {
    // TODO: Dead letter queue setup implementasyonu
}

void EventManager::processMessage(const std::string& consumer_tag,
                                const amqp_envelope_t* envelope) {
    // TODO: Message processing implementasyonu
}

} // namespace event_management
} // namespace security_agent 