#pragma once

#include <string>

// Base64 kodlama fonksiyonları
std::string base64_encode(const unsigned char* data, size_t length);
std::string base64_decode(const std::string& encoded_string); 