#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

//Beacon_frame subtype -> 8
typedef struct {
	char BSSID[20];
	char ESSID[0xff];
	int pwr;
	int beacons;
	int ch;
	int enc;
} beacon_frame;

// probe_request_frame subtype -> 4

typedef struct{
	char BSSID[20];
	char STATION[20];
	int pwr;
	int frames;
	char probes[0xff];
} probe_request_frame;

Param param = {
	.dev_ = NULL
};

void DumpHex(const void* data, int size) {
  char ascii[17];
  int i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';
        if ((i+1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int found_enc(char* packet,int max){
	int chanel_1 = 0;
        for(chanel_1 = packet[0x3d] + 0x3e;0x30 != packet[chanel_1] || 0xdd != packet[chanel_1] && max > chanel_1;chanel_1+=packet[chanel_1+1]+2){}
	if(packet[chanel_1] == 0x30) return packet[chanel_1+4];
	return -1;
}

int found_chanel(char* packet,int max){
	int chanel_1 = 0;
	for(chanel_1 = packet[0x3d] + 0x3e;3 != packet[chanel_1] && max > chanel_1;chanel_1+=packet[chanel_1+1]+2){}
	return packet[chanel_1+2];

}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	
	time_t start_time;
	start_time = time(NULL);

	beacon_frame beacon_save[1000];
	probe_request_frame prob_request_save[1000];
       	int beacon_count = 0;
	int prob_request_count = 0;
	char compare[20];
	int check = -1;
	char tmp[0xff] = {0};

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
		if(packet[24] == 0x80){
			for(int i = 0; i<beacon_count;i++){
				sprintf(compare,"%02x:%02x:%02x:%02x:%02x:%02x",packet[0x28],packet[0x29],packet[0x2a],packet[0x2b],packet[0x2c],packet[0x2d]);
				if(!strncmp(compare,beacon_save[i].BSSID,17)) check = i;
			}
			if(check > -1){
				beacon_save[check].pwr = 0xff-packet[0x12];
                                beacon_save[check].beacons++;
				beacon_save[check].ch=found_chanel(packet,header->caplen);
			}else{
				beacon_save[beacon_count].pwr = 0xff-packet[0x12];
                                beacon_save[beacon_count].beacons=0;
                                sprintf(beacon_save[beacon_count].BSSID,"%02x:%02x:%02x:%02x:%02x:%02x",packet[0x28],packet[0x29],packet[0x2a],packet[0x2b],packet[0x2c],packet[0x2d]);
				for(int j = 0x3e;j<(0x3e + packet[0x3d]);j++){
                                	tmp[j-0x3e] = packet[j];
                                }
                                sprintf(beacon_save[beacon_count].ESSID,"%s",tmp);
				beacon_save[beacon_count].ch = found_chanel(packet,header->caplen);
				beacon_count++;
			}
			check = -1;
			memset(tmp,0,0xff);
			memset(compare,0,20);
		}
		/*
		else if(packet[24] == 0x40){
			printf("Probe Requests Frame %u bytes captured\n", header->caplen);
			DumpHex(packet,header->caplen);
		}*/
		else{
			continue;
		}
		
		printf("\033[2J");
		printf("Starting %ds, ALL BSSID COUNT = %d\n",time(NULL)-start_time,beacon_count);
		printf("BSSID\t\t\tPWR\tBeacons\t   ch\tESSID\n\n");	
		if(beacon_count){
			for(int i = 0;i<beacon_count;i++){
				printf("%s\t-%d\t   %d\t   %d\t %s\n",beacon_save[i].BSSID,beacon_save[i].pwr,beacon_save[i].beacons,beacon_save[i].ch,beacon_save[i].ESSID);

			}
		}
		
	}

	pcap_close(pcap);
}
