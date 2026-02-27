#include "/include/PktB.hpp"
#include "/include/utils.hpp"

uint16_t CheckSum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        uint16_t word = (data[i] << 8) | data[i + 1];
        sum += word;
        if (sum > 0xFFFF)
            sum = (sum & 0xFFFF) + 1;
    }
    if (len & 1) {
        sum += data[len - 1] << 8;
        if (sum > 0xFFFF)
            sum = (sum & 0xFFFF) + 1;
    }
    return ~sum;
}


std::vector<uint8_t> BuildPacket( buildpkt_args pkt_arg , int elaborate_index ,int ip_protocol ,
                                TCPFlag t_flag , Fregmentation t_freg , int peer_seq , 
                                std::string payload )
    {
    
    if(elaborate_index<=1){
        std::cerr <<"    Constructing packet with Source IP address as: "<< pkt_arg.src_ip 
                  << " Destination IP address as: " << pkt_arg.dst_ip << "\n";

    }

    uint32_t src_ip       = htonl(pkt_arg.src_ip);
    uint32_t dst_ip       = htonl(pkt_arg.dst_ip);
    uint16_t src_port     = htons(pkt_arg.src_port);       
    uint16_t dst_port     = htons(pkt_arg.dst_port);
    uint8_t ipv  = pkt_arg.ipv_;  
    bool is_tcp = (ip_protocol==6);
    bool is_udp = (ip_protocol==17);
    
    uint16_t ip_len     = IP_HEADER_LEN;
    uint16_t tcp_len    = TCP_HEADER_LEN;
    uint16_t udp_len    = UDP_HEADER_LEN;

    uint16_t payload_len = payload.size();
    uint16_t transport_len = is_tcp ? tcp_len : udp_len ;
    uint16_t TOTAL_LEN = ip_len + transport_len + payload_len;

    

    uint8_t iph[20] = {0};                  //iph
    iph[0] = (ipv << 4) | (ip_len/4);      //Version (ipv4) And Internal Header Len (5*4=20)
    iph[1] = 0;     //Type of service

    iph[2] = TOTAL_LEN >> 8;        //Header + Payload Len
    iph[3] = TOTAL_LEN & 0xFF;      
    iph[4] = 0x00;      //ID
    iph[5] = 0x00;      //flag

    uint16_t frag = htons(t_freg << 13);    //DF dont freg
    std::memcpy(iph + 6, &frag, 2);        
    iph[8] = pkt_arg.ttl;        //TTL
    iph[9] = ip_protocol;     //Protocol 6=tcp 17=udp
    
    iph[10] = 0;        //Checksums
    iph[11] = 0;
    std::memcpy(iph + 12, &src_ip, 4);
    std::memcpy(iph + 16, &dst_ip, 4);

    uint16_t ip_chk = CheckSum(iph, 20);
    iph[10] = ip_chk >> 8;
    iph[11] = ip_chk & 0xFF;



    uint8_t tcp[20] = {0};                  //TCP
    if(is_tcp){
        
            tcp[0] = src_port >> 8;
            tcp[1] = src_port & 0xFF;
            tcp[2] = dst_port >> 8;
            tcp[3] = dst_port & 0xFF;

            int local_seq = 32;         //temporerly 
            if(TCP_SYN & t_flag){
                uint32_t seq = htonl(rand());
                std::memcpy(tcp + 4, &seq, 4);
            }else{
                uint32_t seq = htonl(local_seq);
                std::memcpy(tcp + 4, &seq, 4);
            }

            if(t_flag & TCP_ACK){
                uint32_t ack = htonl(peer_seq + 1);         // will account for data sent later 
                std::memcpy(tcp+8, &ack , 4);
            }

            tcp[12] = ((tcp_len/4) << 4);      //Data ofset  
            tcp[13] = t_flag;

            uint16_t win = htons(65535);
            std::memcpy(tcp + 14, &win, 2);
            tcp[16] = tcp[17] = 0;
    }

    uint8_t udp[8]={0};                  //UDP
    if(is_udp){
            udp[0] = src_port >> 8;
            udp[1] = src_port & 0xFF;
            udp[2] = dst_port >> 8;
            udp[3] = dst_port & 0xFF;
            uint16_t udp_total_len =  htons(udp_len + payload_len);
            std::memcpy(udp+4 , &udp_total_len , 2);
            udp[6] = udp[7] = 0;
    }


    PseudoHeader_CheckSum ph{};
    ph.src = src_ip;
    ph.dst = dst_ip;
    ph.zero = 0;
    ph.protocol = ip_protocol;
    ph.tcp_len = htons(transport_len); 

    std::vector<uint8_t> chkbuf(sizeof(PseudoHeader_CheckSum) + transport_len + payload_len);

    uint16_t pt_chk;
    if (is_tcp) {
        std::memcpy(chkbuf.data(), &ph, sizeof(ph));
        std::memcpy(chkbuf.data() + sizeof(ph), tcp, tcp_len);
        std::memcpy(chkbuf.data() + sizeof(ph) + tcp_len, payload.data(), payload_len);
    } else if(is_udp) {
        std::memcpy(chkbuf.data(), &ph, sizeof(ph));
        std::memcpy(chkbuf.data() + sizeof(ph), udp, udp_len);
        std::memcpy(chkbuf.data() + sizeof(ph) + udp_len, payload.data(), payload_len);
    }
    
    if(is_tcp){
        pt_chk = CheckSum(chkbuf.data(), chkbuf.size());
        tcp[16] = pt_chk >> 8;
        tcp[17] = pt_chk & 0xFF;
    }else if(is_udp){
        pt_chk = CheckSum(chkbuf.data(), chkbuf.size());
        if (pt_chk == 0){pt_chk = 0xFFFF;};         //special cond
        udp[6] = pt_chk >> 8;
        udp[7] = pt_chk & 0xFF;
    }

    std::vector<uint8_t> packet(TOTAL_LEN);
    std::memcpy(packet.data(), iph, ip_len);

    if (is_tcp) {
    std::memcpy(packet.data() + ip_len, tcp, tcp_len);
    std::memcpy(packet.data() + ip_len + tcp_len,
                payload.data(), payload_len);
    } else if (is_udp) {
        std::memcpy(packet.data() + ip_len, udp, udp_len);
        std::memcpy(packet.data() + ip_len + udp_len,
                    payload.data(), payload_len);
    }

    return packet;
}
