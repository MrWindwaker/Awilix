#pragma once
#include "ebpf/probes.bpf.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <arpa/inet.h>

void initLogger();
void alertUser(struct event *e);
void createLog(struct event *e);