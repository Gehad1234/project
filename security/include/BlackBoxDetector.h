#pragma once
#include "Security_types.h"
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class BlackBoxDetector {
public:
    explicit BlackBoxDetector(const SecurityConfig& cfg);
    void baseline();
    bool scan(std::vector<ThreatEvent>& out);
    std::string issue_dispense_token(const std::string& command_id);
    bool validate_dispense_token(const std::string& command_id, const std::string& token, std::vector<ThreatEvent>& out);
private:
    SecurityConfig cfg_;
    std::unordered_set<std::string> baseline_usb_;
    std::unordered_set<std::string> baseline_serial_;

    std::mutex token_mtx_;
    struct Token {
        std::string value;
        std::chrono::system_clock::time_point expires;
    };
    std::unordered_map<std::string, Token> tokens_;

    std::unordered_set<std::string> usb_devices()  const;
    std::unordered_set<std::string> serial_ports() const;
    std::string make_token(const std::string& cmd, int64_t ts) const;
};
