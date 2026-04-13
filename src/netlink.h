#pragma once

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <functional>
#include <unistd.h>


int initNetlink();
void listenNetlink(int fb, std::function<void(int)> callback);
int subscribeNetlink(int sock);