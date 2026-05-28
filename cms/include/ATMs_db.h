#pragma once
#include <sqlite3.h>
#include <string>
#include <vector>
using namespace std;

struct ATM_Rec {
    int    id;
    string machine_id;  
    string status;
    string location;
    string ATM_ip;
    int    port = 8080;  
};

class ATMsDB {
public:
    explicit ATMsDB(const string& db_path);
    ~ATMsDB();

    void            create_tables();
    void            upsert_ATM(const ATM_Rec& atm);
    ATM_Rec         get_ATM_by_id(int id);
    vector<ATM_Rec> get_all_ATMs();
    void            set_ATM_status(int id, const string& status);

private:
    sqlite3* db_ = nullptr;
    void exec(const string& sql);
};
