#pragma once
#include <string>
#include <vector>

struct CMS_ATM_result {
    long        http_code = 0;
    std::string body;
    std::string error;
    bool ok() const { return error.empty() && http_code >= 200 && http_code < 300; }
};

class CMS_ATM {
public:
    CMS_ATM() = default;

    CMS_ATM_result get(const std::string& atm_ip, int port,
                       const std::string& route);

    CMS_ATM_result post(const std::string& atm_ip, int port,
                        const std::string& route,
                        const std::vector<char>& data = {});

    CMS_ATM_result post_multipart(const std::string& atm_ip, int port,
                                  const std::string& route,
                                  const std::vector<char>& zip_data,
                                  const std::string& metadata_json,
                                  const std::string& filename = "update.zip");

private:
    static std::string build_url(const std::string& atm_ip, int port,
                                 const std::string& route);
};
