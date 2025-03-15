#include <gtest/gtest.h>
#include "modules/event_management/event.hpp"

using namespace security_agent::event_management;

class EventTest : public ::testing::Test {
protected:
    void SetUp() override {
        event = std::make_unique<Event>(
            EventType::MALWARE_DETECTED,
            "test_module",
            SeverityLevel::CRITICAL,
            nlohmann::json{{"test_key", "test_value"}}
        );
    }

    std::unique_ptr<Event> event;
    const std::string test_secret_key = "test_secret_key";
};

TEST_F(EventTest, ConstructorSetsCorrectValues) {
    EXPECT_EQ(event->getType(), EventType::MALWARE_DETECTED);
    EXPECT_EQ(event->getSourceModule(), "test_module");
    EXPECT_EQ(event->getSeverity(), SeverityLevel::CRITICAL);
    EXPECT_EQ(event->getPayload()["test_key"], "test_value");
}

TEST_F(EventTest, SerializationWorks) {
    nlohmann::json serialized = event->toJson();
    
    EXPECT_EQ(static_cast<EventType>(serialized["type"].get<int>()), event->getType());
    EXPECT_EQ(serialized["source_module"], event->getSourceModule());
    EXPECT_EQ(static_cast<SeverityLevel>(serialized["severity"].get<int>()), event->getSeverity());
    EXPECT_EQ(serialized["payload"]["test_key"], "test_value");
}

TEST_F(EventTest, DeserializationWorks) {
    nlohmann::json serialized = event->toJson();
    Event deserialized = Event::fromJson(serialized);
    
    EXPECT_EQ(deserialized.getType(), event->getType());
    EXPECT_EQ(deserialized.getSourceModule(), event->getSourceModule());
    EXPECT_EQ(deserialized.getSeverity(), event->getSeverity());
    EXPECT_EQ(deserialized.getPayload()["test_key"], event->getPayload()["test_key"]);
}

TEST_F(EventTest, SignatureVerificationWorks) {
    std::string signature = event->sign(test_secret_key);
    EXPECT_TRUE(event->verifySignature(signature, test_secret_key));
}

TEST_F(EventTest, SignatureVerificationFailsWithWrongKey) {
    std::string signature = event->sign(test_secret_key);
    EXPECT_FALSE(event->verifySignature(signature, "wrong_key"));
}

TEST_F(EventTest, SignatureVerificationFailsWithTamperedData) {
    std::string signature = event->sign(test_secret_key);
    
    // Create a new event with different data
    Event tampered_event(
        EventType::MALWARE_DETECTED,
        "tampered_module",
        SeverityLevel::CRITICAL,
        nlohmann::json{{"test_key", "tampered_value"}}
    );
    
    EXPECT_FALSE(tampered_event.verifySignature(signature, test_secret_key));
} 