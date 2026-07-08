cmake_minimum_required(VERSION 3.10)
project(LightWeightDNSServer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(server)

target_sources(
  server
  PRIVATE main.cpp udp_dns_server.cpp client.cpp dns.cpp
  PUBLIC udp_dns_server.h client.h dns.h)
