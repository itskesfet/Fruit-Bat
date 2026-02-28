#pragma once
#include "/include/epolli.hpp"
#include "/include/tun.hpp"

#include <unistd.h>


#define IP_HEADER_LEN    20
#define TCP_HEADER_LEN   20
#define UDP_HEADER_LEN    8


enum class TcpState : uint8_t{
    RECEIVED     = 0xFF,
    SYN_SENT     = 0x01,
    SYN_ACKED    = 0x02,
    ESTABLISHED  = 0x09,        
    UNDEFINED    = 0x0E,        
    CLOSED       = 0x0F,        
};

struct UNIQUE_TCP_TABLE{
    uint32_t SourceIP;
    uint32_t DestinationIP;
    uint16_t SourcePort;
    uint16_t DestinationPort;

};

struct TCP_SESSION_META_DATA{
    uint32_t SeqSent = 0;
    uint32_t SeqRecv = 0;

    TcpState State = TcpState::UNDEFINED;
    uint8_t Optional;

};

struct TcpPacketContext {
    UNIQUE_TCP_TABLE key;
    TCP_SESSION_META_DATA meta;
};


struct TCP_CON_TABLE {
    std::vector<std::pair<UNIQUE_TCP_TABLE, TCP_SESSION_META_DATA>> sessions;
};

bool is_root();
int init();

bool is_same_connection(const UNIQUE_TCP_TABLE& incoming ,
                            const UNIQUE_TCP_TABLE& pkt);
void PacketHandler(const TcpPacketContext& TcpId,
                    TCP_CON_TABLE* tcp_table);
