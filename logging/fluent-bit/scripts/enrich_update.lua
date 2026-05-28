local status_severity = {
    updated  = "info",
    updating = "info",
    error    = "error",
    offline  = "warn",
}

function cb_enrich(tag, timestamp, record)
    if tag:find("cms.update") then
        record["event_type"] = "atm_update"
        local status = record["status"] or "unknown"
        record["severity"] = status_severity[status] or "warn"
        if status == "error" then
            record["alert"] = true
            record["alert_reason"] = "ATM update failed: " .. (record["machine_id"] or "unknown")
        end
        local http_code = tonumber(record["http_code"] or 0)
        record["success"] = (http_code >= 200 and http_code < 300)
    elseif tag:find("cms.error") then
        record["event_type"] = "cms_error"
        record["severity"]   = "error"
    elseif tag:find("cms.metrics") then
        record["event_type"] = "system_metrics"
        record["severity"]   = "info"
    end
    record["service"]     = "cms-server"
    record["environment"] = os.getenv("APP_ENV") or "production"
    return 1, timestamp, record
end

function cb_mask_ip(tag, timestamp, record)
    if record["ATM_ip"] then
        local masked = record["ATM_ip"]:gsub("^(%d+%.%d+)%.%d+%.%d+$", "%1.*.*")
        record["ATM_ip_masked"] = masked
        record["ATM_ip"] = nil
    end
    return 1, timestamp, record
end
