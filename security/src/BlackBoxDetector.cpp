#include "../include/BlackBoxDetector.h"
#include <openssl/sha.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;
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

static std::string sha256_string(const std::string& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
    return hex_encode(digest, SHA256_DIGEST_LENGTH);
}

BlackBoxDetector::BlackBoxDetector(const SecurityConfig& cfg) : cfg_(cfg) {}

std::unordered_set<std::string> BlackBoxDetector::usb_devices() const {
    std::unordered_set<std::string> devs;
    if (!fs::exists("/sys/bus/usb/devices")) return devs;
    for (auto& e : fs::directory_iterator("/sys/bus/usb/devices")) {
        std::string id_vendor, id_product;
        std::ifstream v(e.path() / "idVendor"), p(e.path() / "idProduct");
        if (v >> id_vendor && p >> id_product)
            devs.insert(id_vendor + ":" + id_product + "@" + e.path().filename().string());
    }
    return devs;
}

std::unordered_set<std::string> BlackBoxDetector::serial_ports() const {
    std::unordered_set<std::string> ports;
    for (auto& e : fs::directory_iterator("/dev")) {
        std::string n = e.path().filename().string();
        if (n.size() > 3 && n.substr(0,3) == "tty")
            if (n[3] == 'S' || n.substr(3,3) == "USB" || n.substr(3,3) == "ACM")
                ports.insert(e.path().string());
    }
    return ports;
}

void BlackBoxDetector::baseline() {
    baseline_usb_    = usb_devices();
    baseline_serial_ = serial_ports();
}

bool BlackBoxDetector::scan(std::vector<ThreatEvent>& out) {
    bool found = false;
    for (auto& d : usb_devices()) {
        if (!baseline_usb_.count(d)) {
            ThreatEvent ev;
            ev.type        = ThreatType::BBOX_USB_ADDED;
            ev.severity    = default_severity(ev.type);
            ev.machine_id  = cfg_.machine_id;
            ev.description = "New USB device detected: " + d;
            ev.evidence    = "{\"usb\":\"" + d + "\"}";
            out.push_back(ev); found = true;
        }
    }
    for (auto& p : serial_ports()) {
        if (!baseline_serial_.count(p)) {
            ThreatEvent ev;
            ev.type        = ThreatType::BBOX_SERIAL_ADDED;
            ev.severity    = default_severity(ev.type);
            ev.machine_id  = cfg_.machine_id;
            ev.description = "New serial port: " + p;
            ev.evidence    = "{\"port\":\"" + p + "\"}";
            out.push_back(ev); found = true;
        }
    }
    return found;
}

std::string BlackBoxDetector::make_token(const std::string& cmd, int64_t ts) const {
    return sha256_string(cfg_.hmac_secret + cfg_.machine_id + "|" + cmd
                         + "|" + std::to_string(ts));
}

std::string BlackBoxDetector::issue_dispense_token(const std::string& command_id) {
    int64_t ts = unix_now();
    std::string t = make_token(command_id, ts);
    std::lock_guard<std::mutex> lk(token_mtx_);
    tokens_[command_id] = { t, Clock::now() + std::chrono::seconds(30) };
    return t;
}

bool BlackBoxDetector::validate_dispense_token(const std::string& command_id, const std::string& token,
    std::vector<ThreatEvent>& out) {
    std::lock_guard<std::mutex> lk(token_mtx_);
    auto it = tokens_.find(command_id);
    bool ok = (it != tokens_.end()
               && it->second.value == token
               && Clock::now() < it->second.expires);
    if (ok) { tokens_.erase(it); return true; }
    ThreatEvent ev;
    ev.type        = ThreatType::BBOX_UNAUTH_DISPENSE;
    ev.severity    = default_severity(ev.type);
    ev.machine_id  = cfg_.machine_id;
    ev.description = "Dispenser command missing valid token: " + command_id;
    ev.evidence    = "{\"command_id\":\"" + command_id + "\"}";
    out.push_back(ev);
    return false;
}
