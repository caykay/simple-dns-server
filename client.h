#include "shared.h"

#include <netdb.h>

#pragma once

class udp_client
{
  public:
    udp_client(sa_family_t family, int type, int protocol);
    ~udp_client();

    bool is_open() { return s_ != INVALID_SOCKET; }
    int sendto(const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen);
    int close();

  private:
    SOCKET s_ = INVALID_SOCKET;
};
