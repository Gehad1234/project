#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
 
enum class ThreatType : uint8_t {
    NONE               = 0,
    // MitM
    MITM_SIGNATURE_FAIL,    // HMAC verification failed
    MITM_REPLAY_ATTACK,     // nonce already seen
    MITM_CLOCK_SKEW,        // timestamp outside tolerance
    MITM_CERT_MISMATCH,     // TLS fingerprint changed
    // Data Sniffing
    SNIFF_RAW_SOCKET,       // unexpected process holds raw socket
    SNIFF_FOREIGN_PROCESS,  // unauthorized binary running
    // Jackpotting
    JACK_UNKNOWN_PROCESS,   // process not on whitelist
    JACK_UNEXPECTED_CONN,   // outbound to non-allowed IP
    JACK_EXE_TAMPERED,      // executable hash mismatch
    JACK_DISPENSE_RATE,     // dispenser fired too fast
    // Black Box
    BBOX_USB_ADDED,         // unexpected USB device appeared
    BBOX_SERIAL_ADDED,      // unexpected serial port opened
    BBOX_UNAUTH_DISPENSE,   // dispenser command missing valid token
    // Skimming / Spoofing
    SKIM_TIMING_ANOMALY,    // card reader timing outlier
    SKIM_ENTROPY_ANOMALY,   // track data entropy abnormal
    SKIM_DUPLICATE_READ,    // same card read twice rapidly
};
 
enum class ThreatSeverity : uint8_t {
    INFO     = 0,
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4
};
 
// Lockdown state machine  (transitions are monotonically increasing)
enum class LockdownLevel : uint8_t {
    NORMAL     = 0,   // full service
    RESTRICTED = 1,   // no new card sessions, finish in-flight
    ISOLATED   = 2,   // only CMS + LogServer traffic allowed, no transactions
    SHUTDOWN   = 3    // terminate all processes gracefully
};
 
struct ThreatEvent {
    ThreatType      type        = ThreatType::NONE;
    ThreatSeverity  severity    = ThreatSeverity::INFO;
    std::string     machine_id;
    std::string     source_ip;           // IP involved (attacker or self)
    std::string     description;         // human-readable
    std::string     evidence;            // JSON / hex dump
    std::chrono::system_clock::time_point timestamp
        = std::chrono::system_clock::now();
};
 
struct SecurityConfig {
    std::string machine_id;          
    std::string hmac_secret;        
    int         max_clock_skew_sec = 30;
    size_t      nonce_cache_size   = 4096;  
 
    std::vector<std::string> allowed_ips;   // CMS + log server IPs 
    int                      cms_port  = 9090;
    int                      log_port  = 5140;
 
   
    std::vector<std::string> allowed_processes;
 
    std::vector<std::pair<std::string,std::string>> exe_hashes;
 
    int  max_dispense_per_minute = 3;
    int  max_dispense_cents      = 50000;  
 
    // ── Timing (skimming) ─────────────────────
    double card_timing_zscore_threshold = 3.5;
    double track_entropy_low            = 3.5;  // bits/byte thresholds
    double track_entropy_high           = 7.5;
    int    duplicate_card_window_sec    = 5;
 
    // ── Behaviour ─────────────────────────────
    bool auto_isolate_on_critical = true;
    bool report_to_cms_on_threat  = true;
};
 
// Severity helper used by all detectors
inline ThreatSeverity default_severity(ThreatType t) {
    switch (t) {
        case ThreatType::MITM_SIGNATURE_FAIL:   return ThreatSeverity::CRITICAL;
        case ThreatType::MITM_REPLAY_ATTACK:    return ThreatSeverity::CRITICAL;
        case ThreatType::MITM_CERT_MISMATCH:    return ThreatSeverity::CRITICAL;
        case ThreatType::MITM_CLOCK_SKEW:       return ThreatSeverity::HIGH;
        case ThreatType::SNIFF_RAW_SOCKET:      return ThreatSeverity::HIGH;
        case ThreatType::SNIFF_FOREIGN_PROCESS: return ThreatSeverity::HIGH;
        case ThreatType::JACK_UNKNOWN_PROCESS:  return ThreatSeverity::HIGH;
        case ThreatType::JACK_UNEXPECTED_CONN:  return ThreatSeverity::CRITICAL;
        case ThreatType::JACK_EXE_TAMPERED:     return ThreatSeverity::CRITICAL;
        case ThreatType::JACK_DISPENSE_RATE:    return ThreatSeverity::CRITICAL;
        case ThreatType::BBOX_USB_ADDED:        return ThreatSeverity::MEDIUM;
        case ThreatType::BBOX_SERIAL_ADDED:     return ThreatSeverity::HIGH;
        case ThreatType::BBOX_UNAUTH_DISPENSE:  return ThreatSeverity::CRITICAL;
        case ThreatType::SKIM_TIMING_ANOMALY:   return ThreatSeverity::MEDIUM;
        case ThreatType::SKIM_ENTROPY_ANOMALY:  return ThreatSeverity::HIGH;
        case ThreatType::SKIM_DUPLICATE_READ:   return ThreatSeverity::HIGH;
        default:                                return ThreatSeverity::INFO;
    }
}