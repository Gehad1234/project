#pragma once
#include <string>

namespace Route {
    namespace cut {
        constexpr const char* send_file = "/cut/send_file";
    }
    namespace Info {
        constexpr const char* ID      = "/info/id";
        constexpr const char* UpTime  = "/info/uptime";
        constexpr const char* AllInfo = "/info/all";
        constexpr const char* FullInfo= "/info/full";
    }
    namespace Update {
        constexpr const char* InitUpdate      = "/update/init";
        constexpr const char* CurrentFiles    = "/update/current_files";
        constexpr const char* UploadFiles     = "/update/upload";
        constexpr const char* UploadAndUpdate = "/update/upload_and_update";
    }
}
