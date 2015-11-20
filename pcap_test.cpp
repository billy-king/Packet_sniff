#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pcap.h>
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_PKT_SIZE 1600

void usage();

typedef unsigned short u16;
typedef unsigned long u32;

//The first parameter is how long the u16 array is for the second parameter,
//and the second parameter is a u16 array of all the octets of
u16 checksum(u16* headerData, int len){
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = headerData;
	register int nleft = len;

	while(nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}


	sum = (sum >> 16) + (sum & 0xFFFF);

	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}

int main(int argc, char **argv) {
	pcap_t *indesc,*outdesc;
	char error[PCAP_ERRBUF_SIZE];
    	u_char packet[100];
    	int i;
	u_int res;

  /*struct pcap_pkthdr {
  struct timeval ts; /* time stamp
  bpf_u_int32 caplen; /* length of portion present(current capture)
  bpf_u_int32 len; /* length this packet (off wire)
  };*/
	struct pcap_pkthdr *pktheader;
	const u_char *pktdata;
  /*
  struct iphdr{
  #if __BYTE_ORDER == __LITTLE_ENDIAN
      unsigned int ihl:4; header length
      unsigned int version:4;
  #elif __BYTE_ORDER == __BIG_ENDIAN
      unsigned int version:4;
      unsigned int ihl:4;
  #else
  # error "Please fix <bits/endian.h>"
  #endif
      u_int8_t tos;
      u_int16_t tot_len;
      u_int16_t id;
      u_int16_t frag_off;
      u_int8_t ttl;
      u_int8_t protocol;
      u_int16_t check;
      u_int32_t saddr;
      u_int32_t daddr;
      /*The options start here.
  };
  */
	struct iphdr* iph;
  printf("%d %s %s \n" ,argc ,  argv[0] , argv[1]);

    	/* Check the validity of the command line */
	if (argc != 3){
    	printf("usage: %s inerface", argv[0]);
    	return 1;
  }

	/* Open the capture */
	if((indesc = pcap_open_offline(argv[1], error)) == NULL){
    	fprintf(stderr,"\nError opening the input file: %s\n", error);
    	return 1;
	}

	/* Open the output adapter */
	if((outdesc = pcap_open_live(argv[2], 100, 1, 1000, error) ) == NULL){
    	fprintf(stderr,"\nError opening adapter: %s\n", error);
    	return 1;
	}



    	/* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
    	packet[0]=1;
    	packet[1]=1;
    	packet[2]=1;
    	packet[3]=1;
    	packet[4]=1;
    	packet[5]=1;

    	/* set mac source to 2:2:2:2:2:2 */
    	packet[6]=2;
    	packet[7]=2;
    	packet[8]=2;
    	packet[9]=2;
    	packet[10]=2;
    	packet[11]=2;

    	/* Fill the rest of the packet */
    	for(i=12;i<100;i++){
        	packet[i]=i%256;
    	}
	while((res = pcap_next_ex( indesc, &pktheader, &pktdata)) == 1){
		struct iphdr* new_iph;
		struct in_addr new_daddr;
		u_char new_data[MAX_PKT_SIZE];


		if(pktheader->len > MAX_PKT_SIZE) continue;

		memcpy(new_data, pktdata, pktheader->len);
		new_iph = (struct iphdr*) (new_data + sizeof(struct ethhdr));

		iph = (struct iphdr*) (pktdata + sizeof(struct ethhdr));

		//memcpy(&new_iph, iph, sizeof(struct iphdr));
		inet_aton("172.17.0.1", &new_daddr);
		new_iph->daddr = new_daddr.s_addr;
		//printf("check = %u\n", new_iph->check);
		new_iph->check = 0;

		//printf("check = %u, new check = %u, id = %u\n", new_iph->check, checksum((u16*) new_iph, sizeof(struct iphdr)), new_iph->id);
		new_iph->check = checksum((u16*)  new_iph, sizeof(struct iphdr));

		struct in_addr dst_ip;
		dst_ip.s_addr = iph->daddr;
		printf("Read a packet %s\n", inet_ntoa(dst_ip));
		printf("sending data\n");
		pcap_sendpacket(outdesc, new_data, pktheader->len);

	}

    	/* Send down the packet */
    	//pcap_sendpacket(fp, packet, 100);

    	return 0 ;
}

