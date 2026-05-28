#include "../include/CMS_ATM.h"
#include <curl/curl.h>
using namespace std;

static size_t WriteCallback(char* ptr, size_t size, size_t n, void* data) {
    static_cast<string*>(data)->append(ptr, size * n);
    return size * n;
}

string CMS_ATM::build_url(const string& atm_ip, int port, const string& route) {
    return "http://" + atm_ip + ":" + to_string(port) + route;
}

CMS_ATM_result CMS_ATM::get(const string& atm_ip, int port, const string& route) {
    CMS_ATM_result result;
    CURL* curl = curl_easy_init();
    if (!curl) { result.error = "Failed to initialize CURL"; return result; }

    string url = build_url(atm_ip, port, route);
    curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET,        1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &result.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        result.error = "CURL error: " + string(curl_easy_strerror(res));
    else
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.http_code);

    curl_easy_cleanup(curl);
    return result;
}

CMS_ATM_result CMS_ATM::post_multipart(const string& atm_ip, int port,
                                        const string& route,
                                        const vector<char>& zip_data,
                                        const string& metadata_json,
                                        const string& filename) {
    CMS_ATM_result result;
    CURL* curl = curl_easy_init();
    if (!curl) { result.error = "Failed to initialize CURL"; return result; }

    string url = build_url(atm_ip, port, route);
    curl_mime* form = curl_mime_init(curl);

    curl_mimepart* part = curl_mime_addpart(form);
    curl_mime_name(part, "metadata");
    curl_mime_data(part, metadata_json.c_str(), CURL_ZERO_TERMINATED);
    curl_mime_type(part, "application/json");

    part = curl_mime_addpart(form);
    curl_mime_name(part, "files");                    // ATM daemon expects "files"
    curl_mime_data(part, zip_data.data(), zip_data.size());
    curl_mime_filename(part, filename.c_str());        // real filename passed through
    curl_mime_type(part, "application/zip");

    curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST,       form);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &result.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        120L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        result.error = "CURL error: " + string(curl_easy_strerror(res));
    else
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.http_code);

    curl_mime_free(form);
    curl_easy_cleanup(curl);
    return result;
}

CMS_ATM_result CMS_ATM::post(const string& atm_ip, int port,
                               const string& route, const vector<char>& data) {
    CMS_ATM_result result;
    CURL* curl = curl_easy_init();
    if (!curl) { result.error = "Failed to initialize CURL"; return result; }

    string url = build_url(atm_ip, port, route);
    curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST,           1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     data.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,  (long)data.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &result.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        result.error = "CURL error: " + string(curl_easy_strerror(res));
    else
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.http_code);

    curl_easy_cleanup(curl);
    return result;
}
