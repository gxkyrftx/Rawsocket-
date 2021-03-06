#ifndef _INETHEADER_H
#define _INETHEADER_H

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;

#pragma pack(1) 
typedef struct ether_header_t{
    BYTE des_hw_addr[6];    
    BYTE src_hw_addr[6];    
    WORD frametype;         
} ether_header_t;   

//define arp hearder
typedef struct arp_header_t{
    WORD hw_type;           
    WORD prot_type;         
    BYTE hw_addr_len;       
    BYTE prot_addr_len;     
    WORD flag;              
    BYTE send_hw_addr[6];   
    DWORD send_prot_addr;   
    BYTE des_hw_addr[6];    
    DWORD des_prot_addr;    
} arp_header_t;

//define ip hearder
typedef struct ip_header_t{
    BYTE hlen_ver;          
    BYTE tos;               
    WORD total_len;         
    WORD id;                
    WORD flag;              
    BYTE ttl;               
    BYTE protocol;              
    WORD checksum;          
    DWORD src_ip;           
    DWORD des_ip;           
} ip_header_t;

//define udp hearder
typedef struct udp_header_t{
    WORD src_port;          
    WORD des_port;          
    WORD len;               
    WORD checksum;         
} udp_header_t;

//define tcp hearder
typedef struct tcp_header_t{
    WORD src_port;          
    WORD des_port;         
    DWORD seq;              
    DWORD ack;              
    BYTE len_res;           
    BYTE flag;               
    WORD window;            
    WORD checksum;          
    WORD urp;                
} tcp_header_t;

//define icmp hearder
typedef struct icmp_header_t{
    BYTE type;                  
    BYTE code;              
    WORD checksum;          
    WORD id;                   
    WORD seq;               
} icmp_header_t;

typedef struct arp_packet_t{
    ether_header_t etherheader;
    arp_header_t arpheader;
} arp_packet_t;

typedef struct ip_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
} ip_packet_t;

typedef struct tcp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    tcp_header_t tcpheader;
} tcp_packet_t;

typedef struct udp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    udp_header_t udpheader;
} udp_packet_t;

typedef struct icmp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    icmp_header_t icmpheader;
} icmp_packet_t;

#pragma pack()

#endif
