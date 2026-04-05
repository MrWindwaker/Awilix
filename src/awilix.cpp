#include <filesystem>
#include <string>
#include <iostream>
#include <cctype>
#include <algorithm>
#include <fstream>
#include <unordered_set>
#include <vector>
#include <sstream>
#include <bpf/libbpf.h>
#include "ebpf/probes.skel.h"
#include "ebpf/probes.bpf.h"
#include <arpa/inet.h>
#include <unistd.h>

struct probes_bpf *loadBpf()
{
    struct probes_bpf *skel = probes_bpf__open();
    if (!skel)
    {
        std::cerr << "[ERROR] Failed to open BPF skeleton" << std::endl;
        return nullptr;
    }

    if (probes_bpf__load(skel))
    {
        std::cerr << "[ERROR] Failed to load BPF skeleton" << std::endl;
        probes_bpf__destroy(skel);
        return nullptr;
    }

    if (probes_bpf__attach(skel))
    {
        std::cerr << "[ERROR] Failed to attach BPF skeleton" << std::endl;
        probes_bpf__destroy(skel);
        return nullptr;
    }

    std::cerr << "[AWILIX] eBPF probe attached" << std::endl;
    return skel;
}

std::string getParentPid(const std::string &pid)
{
    std::ifstream file("/proc/" + pid + "/stat");
    if (file)
    {
        std::stringstream buf;
        buf << file.rdbuf();
        std::string content = buf.str();

        if (!content.empty())
        {
            size_t closingPnt = content.find(')');
            if (closingPnt == std::string::npos)
                return "";

            std::istringstream iss(content.substr(closingPnt + 1));
            std::string state, ppid;
            iss >> state >> ppid;

            return ppid;
        }

        return "";
    }

    return "";
}

void cleanPids(std::unordered_set<std::string> &pids)
{
    std::vector<std::string> dead;
    for (const std::string &pid : pids)
    {
        if (!std::filesystem::is_directory("/proc/" + pid))
        {
            dead.push_back(pid);
        }
    }

    for (const std::string &pid : dead)
    {
        pids.erase(pid);
        std::cout << "[REMOVED] PID " << pid << std::endl;
    }
}

std::string readCmdline(std::string &pid)
{
    std::ifstream file("/proc/" + pid + "/cmdline");

    if (file)
    {
        std::stringstream buf;
        buf << file.rdbuf();
        std::string content = buf.str();

        if (!content.empty())
        {
            std::replace(content.begin(), content.end(), '\0', ' ');

            return content;
        }

        return "";
    }

    return "";
}

void scanProc(std::unordered_set<std::string> &pids, struct probes_bpf *skel)
{
    for (const auto &entry : std::filesystem::directory_iterator("/proc"))
    {
        std::string pid = entry.path().filename();

        if (std::all_of(pid.begin(), pid.end(), ::isdigit))
        {
            if (pids.find(pid) != pids.end())
            {
                continue;
            }

            std::string content = readCmdline(pid);

            std::string ppid = getParentPid(pid);
            if (!ppid.empty() && pids.find(ppid) != pids.end())
            {
                __u32 pid_num = std::stoul(pid);
                __u8 val = 1;

                bpf_map__update_elem(skel->maps.watched_pids, &pid_num, sizeof(pid_num), &val, sizeof(val), BPF_ANY);
                pids.insert(pid);
                std::cout << "[CHILD] PID " << pid << " (parent: " << ppid << ")" << std::endl;
            }

            if (!content.empty() && content.find("npm install") != std::string::npos)
            {

                __u32 pid_num = std::stoul(pid);
                __u8 val = 1;
                bpf_map__update_elem(skel->maps.watched_pids, &pid_num, sizeof(pid_num), &val, sizeof(val), BPF_ANY);

                pids.insert(pid);
                std::cout << "[DETECTED] PID " << pid << ": " << content << std::endl;
            }
        }
    }
}

bool isAllowed(__u32 ip)
{
    unsigned char *ip_bytes = (unsigned char *)&ip;

    if (ip_bytes[0] == 104 && ip_bytes[1] == 16)
        return true;

    if (ip_bytes[0] == 100 && ip_bytes[1] == 100 && ip_bytes[2] == 100 && ip_bytes[3] == 100)
        return true;

    return false;
}

int handleEvent(void *ctx, void *data, size_t size)
{
    struct event *e = (struct event *)data;

    __u32 ip = e->ip;
    unsigned char *ip_bytes = (unsigned char *)&ip;

    std::string destination = std::to_string(ip_bytes[0]) + "." + std::to_string(ip_bytes[1]) + "." + std::to_string(ip_bytes[2]) + "." + std::to_string(ip_bytes[3]) + ":" + std::to_string(ntohs(e->port));

    if (isAllowed(e->ip))
        std::cout << "[ALLOWED] PID " << e->ip << " (" << e->comm << ") -> " << destination << std::endl;
    else
        std::cout << "[BLOCKED]" << e->ip << " (" << e->comm << ") -> " << destination << std::endl;

    return 0;
}

int main()
{
    std::unordered_set<std::string> pids = {};
    probes_bpf *skel = loadBpf();
    if (!skel)
    {
        std::cerr << "[ERROR] Failed to load eBPF, exiting" << std::endl;
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handleEvent, nullptr, nullptr);

    while (true)
    {
        ring_buffer__poll(rb, 100);
        cleanPids(pids);
        scanProc(pids, skel);

        usleep(1000);
    }

    return 0;
}