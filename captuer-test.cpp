#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

// print usage
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}




// parsiing smac(source mac addr), dmac(destination mac addr) from 'packet'

void pcap_mac(const u_char *pkt){
    /*
    printf("[+] MAC Destination addr : ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
        if(i != 5){
            printf("%02x:\n", *((uint8_t*)ethhdr->ether_dhost+i));
            break;        }
        else{
            printf("%02x\n", *((uint8_t*)ethhdr->ether_dhost+5));
        }
    */

    auto *eth = (ether_header *) pkt;
    for (int i = 0; i < 1; i++ ){     // with simple ui
        printf("#--------- Ethernet Header (MAC addr) ---------#\n");
        printf("[+] source_Mac_Addr : %s\n", ether_ntoa((ether_addr *) eth->ether_shost));
        printf("[+] Destination_Mac_Adrdr : %s\n", ether_ntoa((ether_addr *) eth->ether_dhost));
    }
}

// parsing sip(source ip addr), sip(destination ip addr) from 'packet'
void pcap_ip(const u_char *pkt){
    struct ip *st_ip = (ip *)(pkt+14);

    printf("#--------- IP Header (ipv4 addr) ---------#\n");
    printf("[+] Source_IP_Addr : %s\n", inet_ntoa(st_ip->ip_src));
    printf("[+] Destination_IP_Addr : %s\n", inet_ntoa(st_ip->ip_dst));

};
// parsing port number from 'packet'
void pcap_port(const u_char *pkt){
    struct ip *st_ip = (ip *)(pkt+14);
    auto *tcp = (tcphdr *)(pkt+14+st_ip->ip_hl*4);

    printf("#-------- TCP Header (ipv4 addr) ---------#\n");
    printf("[+] Source_port_num : %d\n", ntohs(tcp->th_sport));
    printf("[+] Destination_Port_Num : %d\n", ntohs(tcp->th_dport));

};
/*
void pcap_payload(){
    printf("#--------- Payload Data (Hexadimecimal 8byte) ---------#\n");
};
*/


int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("#==================================================#\n");
        pcap_mac(packet);
        pcap_ip(packet);
        pcap_port(packet);
        //printf("%x%x%x", packet[0], packet[1], packet[2]);
        //break;
        /*                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
        pcap_payload();
        */
        }

        //printf("%u bytes captured\n", header->caplen);
    pcap_close(pcap);
}








