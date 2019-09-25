#include <pcap.h>
#include <stdio.h>
#include <string.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    printf("Ethernet\n");
    printf("	Source MAC address: ");
    for(int i = 6; i < 12; i++) printf("%02x ", packet[i]);
    printf("\n");
    printf("	Destination MAC address: ");
    for(int i = 0; i < 6; i++) printf("%02x ", packet[i]);
    printf("\n"); 
    if (packet[12] == 0x08 && packet[13] == 0x00){
	printf("IPv4\n");
	printf("	Source IP address: ");
	for(int i = 26; i < 29; i++) printf("%d.", packet[i]);
	printf("%d\n", packet[29]);
        printf("	Destination IP address: ");
        for(int i = 30; i < 33; i++) printf("%d.", packet[i]);
	printf("%d\n", packet[33]);
	if (packet[23] == 0x06){
	    printf("TCP\n");
	    printf("	Source Port: %d\n", packet[35] * 256 + packet[34]);
	    printf("	Destination Port: %d\n", packet[37] * 256 + packet[36]);
		if (header->caplen > 86){
		    printf("payload: ");
		    for(int i = 54; i < 86; i++) printf("%02x", packet[i]); 
		}
		else if (header->caplen > 54){
		    printf("payload: ");
		    for(int i = 54; i < header->caplen; i++) printf("%02x", packet[i]); 
		}
	}
    }
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
}
