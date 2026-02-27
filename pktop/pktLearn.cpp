#include "/include/PktR.hpp"
#include "/include/utils.hpp"

void PacketReader(int fd){

    uint8_t buffer[4096]={0};

    ssize_t nread = read(fd, buffer, sizeof(buffer));
    if(nread<=0){
                            //error handler
        return;
    }

    struct iphdr ip = {0};
    
    if (ip.version != 4) return;
    if (nread < sizeof(iphdr))    return;
    memcpy(&ip,buffer,sizeof(iphdr));

    uint32_t ip_header_len = {0};
    ip_header_len = ip.ihl * 4;
    if (nread < ip_header_len) return;
    if (ip_header_len < IP_HEADER_LEN )    return;
    
    switch (ip.protocol){
        case 17:
            //udp handler

            struct udphdr udp = {0};
            if (nread < ip_header_len + sizeof(struct udphdr))  return;
            memcpy (&udp,    buffer+ip_header_len,   sizeof(udphdr));
            
            uint16_t udp_len = ntohs(udp.len);
            if (nread < ip_header_len + udp_len) return;
            if (udp_len < UDP_HEADER_LEN) return;

            break;

        case 6:
            //tcp handler
            
            if (nread < ip_header_len + sizeof(struct tcphdr)) return;
            struct tcphdr tcp = {0};
            memcpy (&tcp,    buffer+ip_header_len,   sizeof(tcphdr));

            uint32_t tcp_header_len = tcp.doff * 4;
            if (tcp_header_len < 20) return;
            if (nread < ip_header_len + tcp_header_len) return;
        
            break;
        default:
            return;
    }    
    return ;
}
