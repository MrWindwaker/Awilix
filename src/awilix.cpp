#include <filesystem>
#include <string>
#include <iostream>
#include <cctype>
#include <algorithm>
#include <fstream>
#include <unordered_set>
#include <vector>

#include <bpf/libbpf.h>
#include "ebpf/probes.skel.h"
#include "ebpf/probes.bpf.h"
#include <arpa/inet.h>

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

int handleEvent(void *ctx, void *data, size_t size)
{
    struct event *e = (struct event *)data;

    __u32 ip = e->ip;
    unsigned char *ip_bytes = (unsigned char *)&ip;

    std::cout << "[CONNECTION] PID " << e->pid
              << " (" << e->comm << ")"
              << " -> "
              << (int)ip_bytes[0] << "."
              << (int)ip_bytes[1] << "."
              << (int)ip_bytes[2] << "."
              << (int)ip_bytes[3]
              << ":" << ntohs(e->port)
              << std::endl;

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
    }

    return 0;
}