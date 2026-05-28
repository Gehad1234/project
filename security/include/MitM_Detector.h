#pragma once
#include "Security_types.h"
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

class MitM_Detector {
public:
    explicit MitM_Detector(const SecurityConfig& cfg);
    std::string sign(const std::string& payload, uint64_t nonce, int64_t timestamp_unix) const;

    ThreatType  verify(const std::string& payload,const std::string& signature, uint64_t nonce, int64_t timestamp_unix);

    static uint64_t fresh_nonce();

    void pin_certificate(const std::string& sha256_hex);
    ThreatType verify_certificate(const std::string& sha256_hex) const;

private:
    SecurityConfig cfg_;
    std::string    pinned_cert_;

    std::mutex mtx_;
    std::unordered_map<uint64_t,
        std::chrono::system_clock::time_point> seen_nonces_;

    std::string compute_hmac(const std::string& data) const;
    void        purge_old_nonces();
};
