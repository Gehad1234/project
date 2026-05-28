#include "../include/ATM_SecurityService.h"
#include <chrono>
#include <iomanip>
#include <sstream>

using Clock = std::chrono::system_clock;

static int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now().time_since_epoch()).count();
}

ATM_SecurityService::ATM_SecurityService(const SecurityConfig& cfg)
    : cfg_(cfg), mitm_(cfg), sniff_(cfg), jackpot_(cfg), blackbox_(cfg), skim_(cfg)
{
    blackbox_.baseline();
}

ATM_SecurityService::~ATM_SecurityService() { stop(); }

void ATM_SecurityService::on_threat(ThreatCallback cb) {
    std::lock_guard<std::mutex> lk(cb_mtx_);
    callbacks_.push_back(std::move(cb));
}

void ATM_SecurityService::start() {
    running_ = true;
    monitor_thread_ = std::thread(&ATM_SecurityService::monitor_loop, this);
}

void ATM_SecurityService::stop() {
    running_ = false;
    monitor_cv_.notify_all();
    if (monitor_thread_.joinable()) monitor_thread_.join();
}

void ATM_SecurityService::monitor_loop() {
    while (running_) {
        {
            std::unique_lock<std::mutex> lk(monitor_mtx_);
            monitor_cv_.wait_for(lk, std::chrono::seconds(10),
                                 [this]{ return !running_.load(); });
        }
        if (!running_) break;

        std::vector<ThreatEvent> batch;
        sniff_  .scan            (batch);
        jackpot_.scan_processes  (batch);
        jackpot_.scan_connections(batch);
        jackpot_.verify_binaries (batch);
        blackbox_.scan           (batch);

        for (auto& ev : batch) push_event(ev);
    }
}

void ATM_SecurityService::push_event(ThreatEvent e) {
    e.machine_id = cfg_.machine_id;
    e.timestamp  = Clock::now();
    apply_lockdown_policy(e);
    { std::lock_guard<std::mutex> lk(q_mtx_); event_queue_.push(e); }
    std::lock_guard<std::mutex> lk(cb_mtx_);
    for (auto& cb : callbacks_) cb(e);
}

void ATM_SecurityService::apply_lockdown_policy(const ThreatEvent& e) {
    if (!cfg_.auto_isolate_on_critical) return;
    if (e.severity >= ThreatSeverity::CRITICAL) {
        uint8_t desired = static_cast<uint8_t>(LockdownLevel::ISOLATED);
        uint8_t cur     = lockdown_.load();
        if (cur < desired) lockdown_.compare_exchange_strong(cur, desired);
    }
}

bool ATM_SecurityService::verify_request(const std::string& payload,
                                          const std::string& signature,
                                          uint64_t nonce, int64_t ts,
                                          ThreatEvent& ev_out) {
    ThreatType t = mitm_.verify(payload, signature, nonce, ts);
    if (t == ThreatType::NONE) return true;
    ev_out.type        = t;
    ev_out.severity    = default_severity(t);
    ev_out.machine_id  = cfg_.machine_id;
    ev_out.description = to_string(t);
    ev_out.evidence    = "{\"nonce\":" + std::to_string(nonce)
                         + ",\"ts\":"  + std::to_string(ts) + "}";
    push_event(ev_out);
    return false;
}

std::string ATM_SecurityService::sign_response(const std::string& body) {
    return mitm_.sign(body, MitM_Detector::fresh_nonce(), unix_now());
}

std::string ATM_SecurityService::issue_dispense_token(const std::string& command_id) {
    return blackbox_.issue_dispense_token(command_id);
}

bool ATM_SecurityService::authorize_dispense(const std::string& command_id,
                                              const std::string& token,
                                              int amount_cents) {
    std::vector<ThreatEvent> events;
    bool ok = blackbox_.validate_dispense_token(command_id, token, events)
           && !jackpot_.check_dispense_rate(amount_cents, events);
    for (auto& e : events) push_event(e);
    return ok;
}

bool ATM_SecurityService::process_card(double insert_ms,
                                        const std::string& track2,
                                        const std::string& card_hash) {
    std::vector<ThreatEvent> events;
    bool bad = skim_.check_timing   (insert_ms, events)
             | skim_.check_entropy  (track2,    events)
             | skim_.check_duplicate(card_hash, events);
    for (auto& e : events) push_event(e);
    return !bad;
}

LockdownLevel ATM_SecurityService::lockdown_level() const {
    return static_cast<LockdownLevel>(lockdown_.load());
}

void ATM_SecurityService::set_lockdown(LockdownLevel level) {
    uint8_t desired = static_cast<uint8_t>(level);
    uint8_t cur     = lockdown_.load();
    while (cur < desired)
        if (lockdown_.compare_exchange_weak(cur, desired)) break;
}

std::vector<ThreatEvent> ATM_SecurityService::drain_events() {
    std::lock_guard<std::mutex> lk(q_mtx_);
    std::vector<ThreatEvent> out;
    while (!event_queue_.empty()) {
        out.push_back(event_queue_.front());
        event_queue_.pop();
    }
    return out;
}

std::string ATM_SecurityService::to_string(ThreatType t) {
    switch (t) {
        case ThreatType::MITM_SIGNATURE_FAIL:   return "MitM: HMAC signature invalid";
        case ThreatType::MITM_REPLAY_ATTACK:    return "MitM: replay attack (nonce reuse)";
        case ThreatType::MITM_CLOCK_SKEW:       return "MitM: excessive clock skew";
        case ThreatType::MITM_CERT_MISMATCH:    return "MitM: TLS certificate fingerprint changed";
        case ThreatType::SNIFF_RAW_SOCKET:      return "Sniffing: process holds raw socket";
        case ThreatType::SNIFF_FOREIGN_PROCESS: return "Sniffing: unauthorized process";
        case ThreatType::JACK_UNKNOWN_PROCESS:  return "Jackpotting: unknown process";
        case ThreatType::JACK_UNEXPECTED_CONN:  return "Jackpotting: unexpected outbound connection";
        case ThreatType::JACK_EXE_TAMPERED:     return "Jackpotting: binary hash mismatch";
        case ThreatType::JACK_DISPENSE_RATE:    return "Jackpotting: dispenser rate/amount exceeded";
        case ThreatType::BBOX_USB_ADDED:        return "BlackBox: new USB device";
        case ThreatType::BBOX_SERIAL_ADDED:     return "BlackBox: new serial port";
        case ThreatType::BBOX_UNAUTH_DISPENSE:  return "BlackBox: unauthorized dispenser command";
        case ThreatType::SKIM_TIMING_ANOMALY:   return "Skimming: card reader timing anomaly";
        case ThreatType::SKIM_ENTROPY_ANOMALY:  return "Skimming: track data entropy anomaly";
        case ThreatType::SKIM_DUPLICATE_READ:   return "Skimming: duplicate card read";
        default:                                return "Unknown threat";
    }
}