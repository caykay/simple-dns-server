#include <sys/_types/_ssize_t.h>

#define LOOPBACK_ADDR "127.0.0.1"
#define UDP_PORT_STR "12345"
#define MAX_BUF 512
#define ZERO_MEM(buf, len) memset((buf), 0, (len))
#define INVALID_SOCKET ((int)-1)
typedef ssize_t SOCKET;
