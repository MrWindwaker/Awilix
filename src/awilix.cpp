#include <filesystem>
#include <string>
#include <iostream>
#include <cctype>
#include <algorithm>
#include <fstream>
#include <unordered_set>
#include <vector>


int main() {
    std::unordered_set<std::string> pids = {};

    while(true) {
        std::vector<std::string> dead;
        for (const std::string& pid: pids) {
            if (!std::filesystem::is_directory("/proc/" + pid))
            {
                dead.push_back(pid);
            }
        }

        for (const std::string& pid : dead)
        {
            pids.erase(pid);
            std::cout << "[REMOVED] PID " << pid  << std::endl;
        }

        for (const auto &entry : std::filesystem::directory_iterator("/proc"))
        {
            std::string pid = entry.path().filename();

            if (std::all_of(pid.begin(), pid.end(), ::isdigit))
            {
                if(pids.find(pid) != pids.end()) {
                    continue;
                }

                std::ifstream file("/proc/" + pid + "/cmdline");
                if (file)
                {
                    std::stringstream buf;
                    buf << file.rdbuf();
                    std::string content = buf.str();

                    if (!content.empty() && content.find("npm install") != std::string::npos)
                    {

                        pids.insert(pid);

                        std::replace(content.begin(), content.end(), '\0', ' ');
                        std::cout << "[DETECTED] PID " << pid << ": " << content << std::endl;
                    }
                }

                file.close();

                if (!std::filesystem::is_directory("/proc/" + pid)) {
                    
                }
            }
        }

    }

    return 0;
}