#include "client.h"
#include "server.h"
#include "shared.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <thread>

// server worker
void server_worker()
{
    if (server::start_server() != 0)
    {
        printf("%s: server worker exited with code 1", __func__);
    }
}

int main()
{
    std::thread server_thread(server_worker);

    // TODO: wait until server correctly started
    // client
    // char server_ipstr[sizeof()] = LOOPBACK_ADDR;
    addrinfo *server, hint;
    ZERO_MEM(&hint, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_protocol = IPPROTO_UDP;
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    int err = getaddrinfo(LOOPBACK_ADDR, UDP_PORT_STR, &hint, &server);
    if (err != 0)
    {
        printf("Error getting addr. err: %s\n", gai_strerror(err));
        freeaddrinfo(server);
        return 1;
    }

    udp_client client(server->ai_family, server->ai_socktype,
                      server->ai_protocol);

    const char *buf = "Hello World!";
    client.sendto(buf, strlen(buf), MSG_DONTWAIT | MSG_DONTROUTE,
                  server->ai_addr, server->ai_addrlen);
    printf("Client finished sending\n");
    freeaddrinfo(server);

    server_thread.join();
}
