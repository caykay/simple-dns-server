#pragma once

#include <future>

namespace server
{

int start_server(std::promise<void> on_server_init);
} // namespace server
