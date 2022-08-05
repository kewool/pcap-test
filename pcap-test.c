#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <wchar.h>

#define BUFSIZE 1024
#define ICMP 1
#define TCP 6
#define UDP 17

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

unsigned char get4bitFront(unsigned char byte)
{
	return ((unsigned char)0xF0 & byte) >> 4;
}

unsigned char get4bitBack(unsigned char byte)
{
	return (unsigned char)0x0F & byte;
}

unsigned char get3bitFront(unsigned char byte)
{
	return (unsigned char)0xE0 & byte;
}

unsigned char get13bitBack(unsigned char byte)
{
	return (unsigned char)0x1FFF & byte;
}

unsigned char get14bitBack(unsigned char byte)
{
	return (unsigned char)0x0FFF & byte;
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

typedef struct {
    uint8_t oct[6];
} mac_addr;

typedef struct {
    uint8_t oct[4];
} ip_addr;

typedef struct {
    mac_addr dest;
    mac_addr src;
    uint16_t type;
} eth_header;

typedef struct {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_leng;
    uint16_t identification;
    uint16_t flag_frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    ip_addr src;
    ip_addr dest;
} ip_header;

typedef struct{
    uint16_t src;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack;
    uint16_t header_flag;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_header;

typedef struct{
    uint16_t options;
} tcp_option;

typedef struct{
    uint8_t payload[10];
} tcp_payload;

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

// int get_mac_addr_manu(unsigned char* macaddr) { // 랜카드 제조사 getter
//     int sock;
//     int retval;
//     char buf[BUFSIZE];
//     struct hostent *remoteHost;
//     int bytes_read;
//     sock = socket(AF_INET, SOCK_STREAM, 0);
//     if (sock < 0) return 0;
//     remoteHost = gethostbyname("api.macvendors.com");
//     struct sockaddr_in client_addr;
//     client_addr.sin_family = AF_INET;
//     client_addr.sin_port = htons(80);
//     client_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)remoteHost->h_addr_list[0]));
//     retval = connect(sock, (struct sockaddr * ) &client_addr, sizeof(client_addr));
//     if (retval < 0) return 0;
//     char msg[500] = "GET /";
//     for(int i = 0; i < 6; i++) {
//         char a[2];
//         sprintf(a, "%x", macaddr[i]);
//         strcat(msg, a);
//         if(i != 5) strcat(msg, ":");
//     }
//     strcat(msg, " HTTP/1.1\r\n");
//     strcat(msg, "Host: api.macvendors.com:80\r\n\r\n");
//     send(sock, msg, strlen(msg), 0);
//     do {
//         bytes_read = recv(sock, buf, 1024, 0);
//         if (bytes_read == -1) {
//             perror("recv");
//         }
//         else {
//             printf("%s", buf);
//         }
//     } while (bytes_read > 0);
//     close(sock);
//     return 0;
// }

void Gotoxy(int x, int y) {
    printf("\033[%d;%df",y,x);
    fflush(stdout);
}

// void print_frame_top(int type, int end){
//     if(!end) printf("┐     \n");
//     else printf("┐\n");
//     printf(" │ ");
// }
// void print_frame_bottom(int type, int end){
//     if(!end) printf("│     \n");
//     else printf("│\n");
//     printf(" └");
//     switch(type){
//         case 0:
//             for(int i = 0; i < 18; i++){
//                 printf("─");
//             }
//     }
//     printf("┘");
//     if(!end) printf("     ");
// }

int check_tcp(const u_char* packet) {
    ip_header* ip;
    packet += 14;
    ip = (ip_header*)packet;
    if(ip->protocol == TCP) return 1;
    return 0;
}

void parse_ethernet(const u_char* packet) {
    eth_header* eth;
    eth = (eth_header*)packet;
    printf("┌");
    for(int i = 0; i < 21; i++) printf("─");
    printf(" Ethernet MAC Header");
    for(int i = 0; i < 21; i++) printf("─");
    printf("┐\n│ ");
    for(int i = 0; i < 3; i++){
        printf(" ┌");
        if(i != 2){
            for(int j = 0; j < 18; j++){
                printf("─");
            }
            printf("┐    ");
        }
        else {
            for(int j = 0; j < 7; j++){
                printf("─");
            }
            printf("┐");
        }
    }
    printf(" │\n│  │ ");
    for(int i = 0; i < 6; i++){
        printf("%02x", eth->dest.oct[i]);
        if(i != 5) printf(":");
    }
    printf("│     │ ");
    for(int i = 0; i < 6; i++){
        printf("%02x", eth->src.oct[i]);
        if(i != 5) printf(":");
    }
    printf("│     │ 0x%04x│ │\n│ ", ntohs(eth->type));
    for(int i = 0; i < 3; i++){
        printf(" └");
        if(i != 2){
            for(int j = 0; j < 18; j++){
                printf("─");
            }
            printf("┘    ");
        }
        else {
            for(int j = 0; j < 7; j++){
                printf("─");
            }
            printf("┘");
        }
    }
    printf(" │\n│ Destination MAC Address    Source MAC Address         Type   │\n└");
    for(int i = 0; i < 62; i++) printf("─");
    printf("┘\n");
    //get_mac_addr_manu(&eth->dest.oct);
} //이거 너무 노가다..

void parse_ip(const u_char* packet) {
    ip_header* ip;
    ip = (ip_header*)packet;
    printf("----------IP Header----------\n");
    printf("Version: %d\n", get4bitFront(ip->ver_ihl));
    printf("IHL: %d\n", get4bitBack(ip->ver_ihl));
    printf("Total Length: %d\n", ntohs(ip->tot_leng));
    printf("Identification: 0x%04x(%d)\n", ntohs(ip->identification), ntohs(ip->identification));
    printf("Flag: 0x%03x\n", get3bitFront(ip->flag_frag));
    printf("Fragment Offset: %d\n", get13bitBack(ntohs(ip->flag_frag)));
    printf("TTL: %d\n", ip->ttl);
    if(ip->protocol == TCP)
        printf("Protocol: TCP(6)\n");
    else if(ip->protocol == UDP)
        printf("Protocol: UDP(17)\n");
    else if(ip->protocol == ICMP)
        printf("Protocol: ICMP(1)\n");
    else printf("Protocol: %d\n", ip->protocol);
    printf("Header Checksum: 0x%04x\n", ntohs(ip->checksum));
    printf("Source Address: ");
    for(int i = 0; i < 4; i++) {
        printf("%d", ip->src.oct[i]);
        if(i != 3) printf(".");
    }
    printf("\n");
    printf("Destination Address: ");
    for(int i = 0; i < 4; i++) {
        printf("%d", ip->dest.oct[i]);
        if(i != 3) printf(".");
    }
    printf("\n\n");
}

void parse_tcp(const u_char* packet) {
    tcp_header* tcp;
    tcp = (tcp_header*)packet;
    printf("----------TCP Header---------\n");
    printf("Source Port: %d\n", ntohs(tcp->src));
    printf("Destination Port: %d\n", ntohs(tcp->dest));
    printf("Sequence Number(raw): %d\n", ntohl(tcp->seq));
    printf("Acknowledgment Number(raw): %d\n", ntohl(tcp->ack));
    printf("Header Length: %d bytes(%d)\n", get4bitFront(tcp->header_flag) * 4, get4bitFront(tcp->header_flag));
    printf("Flag: 0x%03x\n", get14bitBack(ntohs(tcp->header_flag)));
    printf("Window: %d\n", ntohs(tcp->window));
    printf("Checksum: 0x%04x\n", ntohs(tcp->checksum));
    printf("Urgent Pointer: %d\n", ntohs(tcp->urgent));
}

int check_option(const u_char* packet) {
    tcp_option* option;
    option = (tcp_option*)packet;
    if(ntohs(option->options) == 0x0204) return 1;
    else if(ntohs(option->options) == 0x0101) return 2;
    else if(ntohs(option->options) == 0x0303) return 3;
    else if(ntohs(option->options) == 0x080a) return 4;
    else if(ntohs(option->options) == 0x0402) return 5;
    return 0;
}

void parse_payload(const u_char* packet) {
    tcp_payload* payload;
    payload = (tcp_payload*)packet;
    printf("Payload: ");
    for(int i = 0; i < 10; i++) {
        if(payload->payload[i] != 0)
            printf("%02x ", payload->payload[i]);
    }
}

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
        if(check_tcp(packet)){
            parse_ethernet(packet);
            packet += 14;
            parse_ip(packet);
            packet += 20;
            parse_tcp(packet);
            packet += 20;
            int result = check_option(packet);
            if(result == 2 || result == 4) {
                packet += 12;
            }else if(result == 1) {
                packet += 20;
            }
            parse_payload(packet);
            printf("\n\n--------------------------------------------------------------------------------\n");
        }
	}

	pcap_close(pcap);
}
