#pragma once
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

std::string getParentPid(const std::string &pid);
void cleanPids(std::unordered_set<std::string> &pids);
std::string readCmdline(const std::string &pid);
void scanProc(std::unordered_set<std::string> &pids, struct probes_bpf *skel);
void checkPid(const std::string &pid, std::unordered_set<std::string> &pids, struct probes_bpf *skel);