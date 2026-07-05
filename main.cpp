#include "client.h"
#include "server.h"
#include "shared.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <thread>

int main()
{
    std::promise<void> on_server_init;
    std::future<void> server_ready_signal = on_server_init.get_future();
    std::thread s_t(server::start_server, std::move(on_server_init));

    server_ready_signal.get();

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

    s_t.join();
}
