#include "../include/MitM_Detector.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

using Clock = std::chrono::system_clock;

static std::string hex_encode(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}

static int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now().time_since_epoch()).count();
}

MitM_Detector::MitM_Detector(const SecurityConfig& cfg) : cfg_(cfg) {}

std::string MitM_Detector::compute_hmac(const std::string& data) const {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  len = 0;
    HMAC(EVP_sha256(),
         cfg_.hmac_secret.data(), static_cast<int>(cfg_.hmac_secret.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         digest, &len);
    return hex_encode(digest, len);
}

std::string MitM_Detector::sign(const std::string& payload, uint64_t nonce, int64_t ts) const {
    return compute_hmac(payload + "|" + std::to_string(nonce) + "|" + std::to_string(ts));
}

ThreatType MitM_Detector::verify(const std::string& payload,const std::string& signature, uint64_t nonce, int64_t ts) {
    if (std::abs(unix_now() - ts) > cfg_.max_clock_skew_sec)
        return ThreatType::MITM_CLOCK_SKEW;

    if (sign(payload, nonce, ts) != signature)
        return ThreatType::MITM_SIGNATURE_FAIL;

    std::lock_guard<std::mutex> lk(mtx_);
    purge_old_nonces();
    if (seen_nonces_.count(nonce))
        return ThreatType::MITM_REPLAY_ATTACK;
    seen_nonces_[nonce] = Clock::now();
    return ThreatType::NONE;
}

uint64_t MitM_Detector::fresh_nonce() {
    std::random_device rd;
    std::mt19937_64 rng(rd());
    return rng();
}

void MitM_Detector::pin_certificate(const std::string& sha256_hex) {
    pinned_cert_ = sha256_hex;
}

ThreatType MitM_Detector::verify_certificate(const std::string& sha256_hex) const {
    if (pinned_cert_.empty() || pinned_cert_ == sha256_hex)
        return ThreatType::NONE;
    return ThreatType::MITM_CERT_MISMATCH;
}

void MitM_Detector::purge_old_nonces() {
    auto cutoff = Clock::now()
        - std::chrono::seconds(cfg_.max_clock_skew_sec * 2);
    for (auto it = seen_nonces_.begin(); it != seen_nonces_.end(); )
        it = (it->second < cutoff) ? seen_nonces_.erase(it) : ++it;
    while (seen_nonces_.size() > cfg_.nonce_cache_size)
        seen_nonces_.erase(seen_nonces_.begin());
}
