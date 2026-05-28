#pragma once
#include "Security_types.h"
#include <string>
#include <vector>

class SniffingDetector {
public:
    explicit SniffingDetector(const SecurityConfig& cfg);

    static void secure_zero(std::string& s);
    static void secure_zero(std::vector<uint8_t>& v);

    std::vector<uint8_t> encrypt_track(const std::string& track) const;
    std::string          decrypt_track(const std::vector<uint8_t>& enc) const;

    bool scan(std::vector<ThreatEvent>& out);

private:
    SecurityConfig       cfg_;
    std::vector<uint8_t> session_key_;

    std::vector<std::string> processes_with_raw_sockets() const;
};
