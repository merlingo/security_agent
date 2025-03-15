#include "modules/routing/routing_module.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <yaml-cpp/yaml.h>
#include <curl/curl.h>
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/tcp_socket.h>
#include <rabbitmq-c/framing.h>

namespace security_agent {
namespace routing {

// CURL callback
size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    try {
        s->append((char*)contents, newLength);
    } catch (std::bad_alloc& e) {
        return 0;
    }
    return newLength;
}

RoutingModule::RoutingModule(const std::string& config_path)
    : config_path_(config_path), should_stop_(false) {
    
    // Initialize CURL
    curl_global_init(CURL_GLOBAL_ALL);
    
    // Load config
    loadConfig();
    
    // Start processing thread
    processing_thread_ = std::thread(&RoutingModule::processingThread, this);
}

RoutingModule::~RoutingModule() {
    // Stop processing thread
    should_stop_ = true;
    queue_cv_.notify_all();
    
    if (processing_thread_.joinable()) {
        processing_thread_.join();
    }
    
    // Cleanup CURL
    curl_global_cleanup();
}

SendResult RoutingModule::sendData(const nlohmann::json& data, const std::string& index) {
    // Check if index is configured
    if (!isIndexConfigured(index)) {
        return SendResult::INVALID_DATA;
    }
    
    // Check if data is empty
    if (data.empty()) {
        return SendResult::INVALID_DATA;
    }
    
    // Add to queue
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        
        // Check queue size
        if (data_queue_.size() >= config_.queue_size_limit) {
            return SendResult::QUEUE_FULL;
        }
        
        // Add to queue
        QueueItem item;
        item.data = data;
        item.index = index;
        item.retry_count = 0;
        item.timestamp = std::chrono::system_clock::now();
        
        data_queue_.push(item);
    }
    
    // Notify processing thread
    queue_cv_.notify_one();
    
    return SendResult::SUCCESS;
}

void RoutingModule::reloadConfig() {
    loadConfig();
}

void RoutingModule::loadConfig() {
    try {
        YAML::Node config = YAML::LoadFile(config_path_);
        auto routing_config = config["routing_module"];
        
        // Basic configuration
        config_.enabled = routing_config["enabled"] ? routing_config["enabled"].as<bool>() : true;
        config_.retry_count = routing_config["retry_count"] ? routing_config["retry_count"].as<int>() : 3;
        config_.retry_delay_seconds = routing_config["retry_delay_seconds"] ? routing_config["retry_delay_seconds"].as<int>() : 5;
        config_.queue_size_limit = routing_config["queue_size_limit"] ? routing_config["queue_size_limit"].as<int>() : 1000;
        config_.batch_size = routing_config["batch_size"] ? routing_config["batch_size"].as<int>() : 100;
        config_.processing_interval_seconds = routing_config["processing_interval_seconds"] ? routing_config["processing_interval_seconds"].as<int>() : 5;
        
        // Server configuration
        auto server_config = routing_config["server"];
        if (server_config) {
            config_.server.host = server_config["host"] ? server_config["host"].as<std::string>() : "localhost";
            config_.server.port = server_config["port"] ? server_config["port"].as<int>() : 9200;
            config_.server.username = server_config["username"] ? server_config["username"].as<std::string>() : "";
            config_.server.password = server_config["password"] ? server_config["password"].as<std::string>() : "";
            config_.server.use_ssl = server_config["use_ssl"] ? server_config["use_ssl"].as<bool>() : false;
            config_.server.ca_cert_path = server_config["ca_cert_path"] ? server_config["ca_cert_path"].as<std::string>() : "";
        } else {
            config_.server.host = "localhost";
            config_.server.port = 9200;
            config_.server.username = "";
            config_.server.password = "";
            config_.server.use_ssl = false;
            config_.server.ca_cert_path = "";
        }
        
        // Destinations
        auto destinations_config = routing_config["destinations"];
        if (destinations_config) {
            config_.destinations.clear();
            for (const auto& destination : destinations_config) {
                std::string name = destination.first.as<std::string>();
                std::string type_str = destination.second.as<std::string>();
                
                DestinationType type;
                if (type_str == "elasticsearch") {
                    type = DestinationType::ELASTICSEARCH;
                } else if (type_str == "logstash") {
                    type = DestinationType::LOGSTASH;
                } else if (type_str == "rabbitmq") {
                    type = DestinationType::RABBITMQ;
                } else if (type_str == "file") {
                    type = DestinationType::FILE;
                } else {
                    type = DestinationType::CUSTOM;
                }
                
                config_.destinations[name] = type;
            }
        }
        
        // Index configurations
        auto indices_config = routing_config["indices"];
        if (indices_config) {
            index_configs_.clear();
            for (const auto& index : indices_config) {
                std::string name = index.first.as<std::string>();
                auto index_config = index.second;
                
                IndexConfig config;
                config.name = name;
                
                std::string destination_type = index_config["destination_type"] ? index_config["destination_type"].as<std::string>() : "elasticsearch";
                if (destination_type == "elasticsearch") {
                    config.destination_type = DestinationType::ELASTICSEARCH;
                } else if (destination_type == "logstash") {
                    config.destination_type = DestinationType::LOGSTASH;
                } else if (destination_type == "rabbitmq") {
                    config.destination_type = DestinationType::RABBITMQ;
                } else if (destination_type == "file") {
                    config.destination_type = DestinationType::FILE;
                } else {
                    config.destination_type = DestinationType::CUSTOM;
                }
                
                config.destination_url = index_config["destination_url"] ? index_config["destination_url"].as<std::string>() : "";
                config.mapping = index_config["mapping"] ? index_config["mapping"].as<std::string>() : "";
                config.use_timestamp = index_config["use_timestamp"] ? index_config["use_timestamp"].as<bool>() : true;
                config.timestamp_field = index_config["timestamp_field"] ? index_config["timestamp_field"].as<std::string>() : "@timestamp";
                config.index_pattern = index_config["index_pattern"] ? index_config["index_pattern"].as<std::string>() : name + "-%Y.%m.%d";
                
                index_configs_[name] = config;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error loading routing config: " << e.what() << std::endl;
        
        // Default configuration
        config_.enabled = true;
        config_.retry_count = 3;
        config_.retry_delay_seconds = 5;
        config_.queue_size_limit = 1000;
        config_.batch_size = 100;
        config_.processing_interval_seconds = 5;
        
        config_.server.host = "localhost";
        config_.server.port = 9200;
        config_.server.username = "";
        config_.server.password = "";
        config_.server.use_ssl = false;
        config_.server.ca_cert_path = "";
        
        config_.destinations.clear();
        config_.destinations["elasticsearch"] = DestinationType::ELASTICSEARCH;
        
        index_configs_.clear();
        
        // Default index config
        IndexConfig default_config;
        default_config.name = "default";
        default_config.destination_type = DestinationType::ELASTICSEARCH;
        default_config.destination_url = "http://localhost:9200";
        default_config.mapping = "";
        default_config.use_timestamp = true;
        default_config.timestamp_field = "@timestamp";
        default_config.index_pattern = "default-%Y.%m.%d";
        
        index_configs_["default"] = default_config;
    }
}

void RoutingModule::processingThread() {
    while (!should_stop_) {
        std::vector<QueueItem> items_to_process;
        
        // Get items from queue
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            // Wait for items or stop signal
            queue_cv_.wait_for(lock, std::chrono::seconds(config_.processing_interval_seconds),
                              [this]() { return !data_queue_.empty() || should_stop_; });
            
            // If stopping and queue is empty, exit
            if (should_stop_ && data_queue_.empty()) {
                break;
            }
            
            // Get items to process
            int count = 0;
            while (!data_queue_.empty() && count < config_.batch_size) {
                items_to_process.push_back(data_queue_.front());
                data_queue_.pop();
                count++;
            }
        }
        
        // Process items
        for (auto& item : items_to_process) {
            // Send data
            SendResult result = sendDataInternal(item.data, item.index);
            
            // Handle result
            if (result != SendResult::SUCCESS) {
                // Retry if needed
                if (item.retry_count < config_.retry_count) {
                    item.retry_count++;
                    
                    // Add back to queue
                    std::lock_guard<std::mutex> lock(queue_mutex_);
                    data_queue_.push(item);
                } else {
                    // Log error
                    std::cerr << "Failed to send data to " << item.index << " after " << item.retry_count << " retries" << std::endl;
                }
            }
        }
    }
}

SendResult RoutingModule::sendDataInternal(const nlohmann::json& data, const std::string& index) {
    // Check if index is configured
    auto it = index_configs_.find(index);
    if (it == index_configs_.end()) {
        return SendResult::INVALID_DATA;
    }
    
    // Get index config
    const IndexConfig& index_config = it->second;
    
    // Add timestamp if needed
    nlohmann::json data_with_timestamp = data;
    if (index_config.use_timestamp) {
        auto now = std::chrono::system_clock::now();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
        data_with_timestamp[index_config.timestamp_field] = now_ms;
    }
    
    // Send based on destination type
    switch (index_config.destination_type) {
        case DestinationType::ELASTICSEARCH:
            return sendToElasticsearch(data_with_timestamp, index_config);
        case DestinationType::LOGSTASH:
            return sendToLogstash(data_with_timestamp, index_config);
        case DestinationType::RABBITMQ:
            return sendToRabbitMQ(data_with_timestamp, index_config);
        case DestinationType::FILE:
            return sendToFile(data_with_timestamp, index_config);
        case DestinationType::CUSTOM:
            return sendToCustom(data_with_timestamp, index_config);
        default:
            return SendResult::INVALID_DATA;
    }
}

SendResult RoutingModule::sendToElasticsearch(const nlohmann::json& data, const IndexConfig& index_config) {
    // Format index name with date
    std::string formatted_index = index_config.index_pattern;
    
    // Replace date pattern
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    char buffer[100];
    std::strftime(buffer, sizeof(buffer), formatted_index.c_str(), std::localtime(&now_time_t));
    formatted_index = buffer;
    
    // Create URL
    std::string url = index_config.destination_url;
    if (url.empty()) {
        url = (config_.server.use_ssl ? "https://" : "http://") +
              config_.server.host + ":" + std::to_string(config_.server.port);
    }
    
    url += "/" + formatted_index + "/_doc";
    
    // Create CURL handle
    CURL* curl = curl_easy_init();
    if (!curl) {
        return SendResult::FAILURE;
    }
    
    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    
    // Set method to POST
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    
    // Set data
    std::string json_str = data.dump();
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
    
    // Set content type
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    // Set authentication if needed
    if (!config_.server.username.empty()) {
        std::string auth = config_.server.username + ":" + config_.server.password;
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth.c_str());
    }
    
    // Set SSL options if needed
    if (config_.server.use_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        
        if (!config_.server.ca_cert_path.empty()) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, config_.server.ca_cert_path.c_str());
        }
    }
    
    // Set response callback
    std::string response_string;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    // Check result
    SendResult result;
    if (res != CURLE_OK) {
        result = SendResult::CONNECTION_ERROR;
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        
        if (http_code >= 200 && http_code < 300) {
            result = SendResult::SUCCESS;
        } else if (http_code == 401 || http_code == 403) {
            result = SendResult::AUTHENTICATION_ERROR;
        } else if (http_code >= 500) {
            result = SendResult::RETRY;
        } else {
            result = SendResult::FAILURE;
        }
    }
    
    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return result;
}

SendResult RoutingModule::sendToLogstash(const nlohmann::json& data, const IndexConfig& index_config) {
    // Create URL
    std::string url = index_config.destination_url;
    if (url.empty()) {
        url = (config_.server.use_ssl ? "https://" : "http://") +
              config_.server.host + ":" + std::to_string(config_.server.port);
    }
    
    // Create CURL handle
    CURL* curl = curl_easy_init();
    if (!curl) {
        return SendResult::FAILURE;
    }
    
    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    
    // Set method to POST
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    
    // Set data
    std::string json_str = data.dump();
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
    
    // Set content type
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    // Set authentication if needed
    if (!config_.server.username.empty()) {
        std::string auth = config_.server.username + ":" + config_.server.password;
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth.c_str());
    }
    
    // Set SSL options if needed
    if (config_.server.use_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        
        if (!config_.server.ca_cert_path.empty()) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, config_.server.ca_cert_path.c_str());
        }
    }
    
    // Set response callback
    std::string response_string;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    // Check result
    SendResult result;
    if (res != CURLE_OK) {
        result = SendResult::CONNECTION_ERROR;
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        
        if (http_code >= 200 && http_code < 300) {
            result = SendResult::SUCCESS;
        } else if (http_code == 401 || http_code == 403) {
            result = SendResult::AUTHENTICATION_ERROR;
        } else if (http_code >= 500) {
            result = SendResult::RETRY;
        } else {
            result = SendResult::FAILURE;
        }
    }
    
    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return result;
}

SendResult RoutingModule::sendToRabbitMQ(const nlohmann::json& data, const IndexConfig& index_config) {
    // Create connection
    amqp_connection_state_t conn = amqp_new_connection();
    amqp_socket_t* socket = amqp_tcp_socket_new(conn);
    if (!socket) {
        amqp_destroy_connection(conn);
        return SendResult::CONNECTION_ERROR;
    }
    
    // Connect to server
    std::string host = config_.server.host;
    int port = config_.server.port;
    
    int status = amqp_socket_open(socket, host.c_str(), port);
    if (status != AMQP_STATUS_OK) {
        amqp_destroy_connection(conn);
        return SendResult::CONNECTION_ERROR;
    }
    
    // Login
    amqp_rpc_reply_t login_reply = amqp_login(conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN,
                                             config_.server.username.c_str(), config_.server.password.c_str());
    if (login_reply.reply_type != AMQP_RESPONSE_NORMAL) {
        amqp_destroy_connection(conn);
        return SendResult::AUTHENTICATION_ERROR;
    }
    
    // Open channel
    amqp_channel_open(conn, 1);
    amqp_rpc_reply_t channel_reply = amqp_get_rpc_reply(conn);
    if (channel_reply.reply_type != AMQP_RESPONSE_NORMAL) {
        amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
        amqp_destroy_connection(conn);
        return SendResult::FAILURE;
    }
    
    // Declare exchange
    std::string exchange = "amq.direct";
    amqp_exchange_declare(conn, 1, amqp_cstring_bytes(exchange.c_str()), amqp_cstring_bytes("direct"),
                         0, 0, 0, 0, amqp_empty_table);
    amqp_rpc_reply_t exchange_reply = amqp_get_rpc_reply(conn);
    if (exchange_reply.reply_type != AMQP_RESPONSE_NORMAL) {
        amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS);
        amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
        amqp_destroy_connection(conn);
        return SendResult::FAILURE;
    }
    
    // Publish message
    std::string json_str = data.dump();
    std::string routing_key = index_config.name;
    
    amqp_basic_properties_t props;
    props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.content_type = amqp_cstring_bytes("application/json");
    props.delivery_mode = 2; // persistent delivery mode
    
    int publish_status = amqp_basic_publish(conn, 1, amqp_cstring_bytes(exchange.c_str()),
                                          amqp_cstring_bytes(routing_key.c_str()),
                                          0, 0, &props, amqp_cstring_bytes(json_str.c_str()));
    
    // Close connection
    amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS);
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
    
    if (publish_status != AMQP_STATUS_OK) {
        return SendResult::FAILURE;
    }
    
    return SendResult::SUCCESS;
}

SendResult RoutingModule::sendToFile(const nlohmann::json& data, const IndexConfig& index_config) {
    // Get file path
    std::string file_path = index_config.destination_url;
    if (file_path.empty()) {
        file_path = index_config.name + ".json";
    }
    
    // Format file path with date
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    char buffer[100];
    std::strftime(buffer, sizeof(buffer), file_path.c_str(), std::localtime(&now_time_t));
    file_path = buffer;
    
    // Open file
    std::ofstream file(file_path, std::ios::app);
    if (!file) {
        return SendResult::FAILURE;
    }
    
    // Write data
    file << data.dump() << std::endl;
    
    // Close file
    file.close();
    
    return SendResult::SUCCESS;
}

SendResult RoutingModule::sendToCustom(const nlohmann::json& data, const IndexConfig& index_config) {
    // This is a placeholder for custom destination implementation
    // In a real application, this would be implemented based on specific requirements
    
    return SendResult::SUCCESS;
}

} // namespace routing
} // namespace security_agent 