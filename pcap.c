#include <pcap.h>//통신 툴
#include <stdbool.h>//True False사용하기 위한 헤더파일
#include <stdio.h>//표준 입출력
#include <stdint.h>
#include <netinet/in.h>

const struct ETHERNET_HEADER *ethernet;
const struct IP_HEADER *ip;
const struct TCP_HEADER *tcp;
const struct Payload *payload;
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

struct ETHERNET_HEADER{
	__u_char mac_dst[6];
	__u_char mac_src[6];
	__u_char type[2];
};

struct IP_HEADER{
	uint32_t trash1;
	uint32_t trash2;
	uint32_t trash3;
	uint8_t ip_src[4];
	uint8_t ip_dst[4];
};

struct TCP_HEADER{
	uint16_t src_port;
	uint16_t dst_port;
};

struct Payload{
	uint8_t payload[5]
};

typedef struct {//그냥 구조체랑 다른게 별명을 붙여줄 수 있음
	char* dev_;
} Param;

Param param = {
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

void print_mac(__u_char mac_dst[6]){
	for(int i=0;i<6;i++){
			printf("%02x",mac_dst[i]);
			if(i==5){
				continue;
			}
			printf(":");
		}
}

void print_ip(uint8_t ip_src[4]){
	for(int i=0;i<4;i++){
			printf("%d",ip_src[i]);
			if(i==3){
				continue;
			}
			printf(".");
		}
}

void print_port(uint16_t src_port){
	printf("%d",ntohs(src_port));
}
void print_payload(uint8_t payload[20]){
	for(int i=0; i<20;i++){
		printf("%02X", payload[i]);
	}
	printf("\n");
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
		const __u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		ethernet = (struct ETHERNET_HEADER*)(packet);
		ip = (struct IP_HEADER*)(packet+14);
		tcp = (struct TCP_HEADER*)(packet+34);
		payload = (struct Payload*)(packet+54);
		
		printf("MAC_ADDRESS: src ");
		print_mac(ethernet->mac_dst);
		printf(" MAC_ADDRESS: dst ");
		print_mac(ethernet->mac_src);
		printf("\n");
		printf("IP_ADDRESS: src ");
		print_ip(ip->ip_src);
		printf(" IP_ADDRESS: dst ");
		print_ip(ip->ip_dst);
		printf("\n");
		printf("PORT NUM: src ");
		print_port(tcp->src_port);
		printf(" PORT NUM: dst ");
		print_port(tcp->dst_port);
		printf("\n");
		printf("Payload: ");
		print_payload(payload->payload);
		
	}

	pcap_close(pcap);
}
