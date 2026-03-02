
#include "utils.hpp"
#include "PktW.hpp"
#include "PktB.hpp"


bool is_same_connection(const UNIQUE_TCP_TABLE& incoming ,const UNIQUE_TCP_TABLE& pkt){
    if( incoming.SourceIP == pkt.SourceIP &&
        incoming.DestinationIP == pkt.DestinationIP &&
        incoming.SourcePort == pkt.SourcePort &&
        incoming.DestinationPort == pkt.DestinationPort
       ){
        return true;
       }
    return false;
}

void execute(const TCP_PACKET_CONTEXT& TcpId ,const Actiontype& action ,int tun_fd){
    struct buildpkt_args pkt_args;
    pkt_args.src_ip     = TcpId.key.DestinationIP;
    pkt_args.dst_ip     = TcpId.key.SourceIP;
    pkt_args.src_port   = TcpId.key.DestinationPort;
    pkt_args.dst_port   = TcpId.key.SourcePort;
    pkt_args.ttl        = 64;
    pkt_args.ipv_       = 4;
    std::string payload = "";
    uint32_t ack_seq    = 0;
    uint32_t seq        = 0;
    switch(action) {
        case Actiontype::SEND_SYN_ACK: {
            
            ack_seq = TcpId.meta.SeqRecv +1 ;
            seq     = 43;               //tempry

            TCPFlag t_flag = static_cast<TCPFlag>(static_cast<uint8_t>(TCPFlag::TCP_SYN) | static_cast<uint8_t>(TCPFlag::TCP_ACK));
            std::vector<uint8_t> built_packet =  BuildPacket( pkt_args ,
                                TCP_PROTOCOL ,t_flag , 
                                seq , ack_seq,
                                DF, payload);
            PacketWriter(tun_fd, built_packet);
            break;
        }
        case Actiontype::SEND_ACK: {
            ack_seq = TcpId.meta.SeqRecv ;
            seq     = TcpId.meta.SeqSent ;
            std::vector<uint8_t> built_packet =  BuildPacket( pkt_args ,
                                TCP_PROTOCOL , TCPFlag::TCP_ACK , 
                                seq , ack_seq,
                                DF, payload);
            PacketWriter(tun_fd, built_packet);
            break;
        }
        case Actiontype::SEND_DATA_ACK:{
            ack_seq = TcpId.meta.SeqRecv + TcpId.meta.PayloadSize + (TcpId.meta.flag == TCPFlag::TCP_SYN? 1 : 0) + (TcpId.meta.flag == TCPFlag::TCP_FIN? 1 : 0) ;
            seq     = TcpId.meta.SeqSent ;
            std::vector<uint8_t> built_packet =  BuildPacket( pkt_args ,
                                TCP_PROTOCOL , TCPFlag::TCP_ACK , 
                                seq , ack_seq,
                                DF, payload);
            PacketWriter(tun_fd, built_packet);
            break;
        }
        case Actiontype::CLOSE:

            break;
        default:
            break;
    }

    return;
}

int Search_Session_in_TCP_CON_TABLE(const TCP_PACKET_CONTEXT& TcpId  , TCP_CON_TABLE* tcp_table ){
    int pos = 0;
    for(auto &it : tcp_table->sessions){
        const UNIQUE_TCP_TABLE& key = it.first;
        const UNIQUE_TCP_TABLE& incoming = TcpId.key;
        if(is_same_connection(incoming,key)){
            return pos;    
        }
        ++pos;
    }
    return -1;
}

void PacketHandler(const TCP_PACKET_CONTEXT& TcpId, TCP_CON_TABLE* tcp_table ,int tun_fd){

            int pos = Search_Session_in_TCP_CON_TABLE(TcpId , tcp_table );
            if( pos < 0){
                //register new stream
            }
            auto& it = tcp_table->sessions[pos];

            TCP_PACKET_CONTEXT session;
            session.key = it.first;
            session.meta = it.second;
            if(session.meta.State       == TcpState::RECEIVED_SYN){
                execute(TcpId ,Actiontype::SEND_SYN_ACK  ,tun_fd);
            }else if(session.meta.State == TcpState::SYN_ACKED){
                
            }else if(session.meta.State == TcpState::ESTABLISHED){
                execute(TcpId ,Actiontype::SEND_DATA_ACK ,tun_fd);
            }else if(session.meta.State == TcpState::CLOSED){
                //to be done
            }else{
                
            }
    
    return;
}
