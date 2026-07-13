#pragma once

#include <future>

namespace server
{
#define LABEL_SIZE_MAX 64 // max label buffer size (63 + 1) null terminated
int start_server(std::promise<void> on_server_init);
} // namespace server
