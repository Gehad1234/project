#pragma once
#include <crow.h>
#include "CMS_ATM.h"
#include "ATMs_db.h"
#include <vector>
#include <string>
using namespace std;

class CMS_server {
public:
    explicit CMS_server(uint16_t port = 9090);
    void run();

private:
    crow::SimpleApp app;
    uint16_t        port;
    ATMsDB          db;
    CMS_ATM         atm_;

    ATM_Rec         resolve    (const crow::request& req);
    vector<ATM_Rec> resolve_all(const crow::request& req);
    static crow::response format_response(const CMS_ATM_result& result);

    crow::response route_cut_send_file      (const crow::request& req);
    crow::response route_machine_id         (const crow::request& req);
    crow::response route_machine_uptime     (const crow::request& req);
    crow::response route_machine_info       (const crow::request& req);
    crow::response route_init_update        (const crow::request& req);
    crow::response route_current_files      (const crow::request& req);
    crow::response route_upload_files       (const crow::request& req);
    crow::response route_upload_and_update  (const crow::request& req);
};
