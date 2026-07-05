#pragma once

#include <future>

namespace server
{

struct dns_query_t
{
    char q_name[256]; // domain name
    int16_t q_type;   // DNS record type (i.e. A for ipv4 or AAAA for ipv6)
    int16_t q_class;
};

struct dns_answer_t
{
    char q_name[256]; // can probably be optimized to a ptr of
                      // dns_query_t::q_name
    int16_t a_type;   // DNS record type
    int16_t a_class;
    int32_t ttl; // in seconds
    int16_t c_name_len;
    char c_name[256];
};

/**
 * rr - resource record
 */

struct dns_payload_t // as a udp payload
{
    /** DNS HEADER **/

    int16_t transaction_id;
    int16_t flags;
    int16_t questions_count; // QDCOUNT - typically one for udp
    int16_t answers_rr_count;
    int16_t authoritative_rr_count;
    int16_t additional_rr_count;

    /** DNS BODY **/

    dns_query_t query; // dns over udp playload is limited to 1 query per packet
    dns_answer_t answers[30]; // assuming or expecting 16 - 24 answer range, but
                              // it could be more than this
};
int start_server(std::promise<void> on_server_init);
} // namespace server
