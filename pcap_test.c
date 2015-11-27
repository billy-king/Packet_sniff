#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <pcap.h>
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define MAX_PACKET_SIZE 1600 //bytes
#define Promiscuous 1
#define TIME_OUT 1000 //ms

void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}
void printf_ethernet_header(const u_char *pktdata){
/*struct ether_header
  struct ether_header{
  u_char  ether_dhost; //[6]Destination MAC address.

  u_char  ether_shost; //[6]  Source MAC address.

  u_short   ether_type; //Protocol type.
  }
*/
  struct ether_header *ethptr;
  u_char *ptr;
  int i;

  i = ETHER_ADDR_LEN;
  ptr = ethptr->ether_dhost;
  printf(" Destination MAC Address:  ");
  do{
      printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
  }while(--i>0);
  printf("\n");

  ptr = ethptr->ether_shost;
  i = ETHER_ADDR_LEN;
  printf(" Source MAC Address:  ");
  do{
      printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
  }while(--i>0);
  printf("\n");
}

void printf_ip_header(const u_char *pktdata){
/*struct iphdr
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
  struct iphdr *iph;
  iph = (struct iphdr*)(pktdata + sizeof(struct ethhdr));
  //printf_ethernet_header(pktdata);
  printf("\n");
  printf("IP Header\n");
  printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
  printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
  printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
  printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
  printf("   |-Identification    : %d\n",ntohs(iph->id));
  //printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
  //printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
  //printf("   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
  printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
  printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
  printf("   |-Checksum : %d\n",ntohs(iph->check));
  printf("   |-Source IP        : "); print_ip(ntohl(iph->saddr));
  printf("   |-Destination IP   : "); print_ip(ntohl(iph->daddr));

}

void printf_tcp_header(const u_char *pktdata){

  /*struct tcphdr {
    unsigned short source;
    unsigned short dest;
    unsigned long seq;
    unsigned long ack_seq;
    unsigned short doff:4;
    unsigned char syn;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
  };
  */
  struct tcphdr *tcph;
  unsigned short iphdrlen;

  struct iphdr *iph;
  iph = (struct iphdr*)(pktdata + sizeof(struct ethhdr));
  iphdrlen = iph->ihl*4;

  tcph=(struct tcphdr*)(pktdata + iphdrlen + sizeof(struct ethhdr));

  printf_ip_header(pktdata);

  printf("\n\n***********************TCP Packet*************************\n");
  printf("\n");
  printf("TCP Header\n");
  printf("   |-Source Port      : %u\n",ntohs(tcph->source));
  printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
  printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
  printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
  printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
  //printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
  //printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
  printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
  printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
  printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
  printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
  printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
  printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
  printf("   |-Window         : %d\n",ntohs(tcph->window));
  printf("   |-Checksum       : %d\n",ntohs(tcph->check));
  printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
  printf("\n");
  printf("                        DATA Dump                         ");
  printf("\n");

}

void process_packet(u_char *args, const struct pcap_pkthdr *pktheader, const u_char *pktdata){
  int size = pktheader->len;
  printf("pktheader length= %d\n" , size);

  struct iphdr *iph = (struct iphdr*)(pktdata + sizeof(struct ethhdr));

  switch (iph->protocol) //Check the Protocol and do accordingly...
  {
      case 1:  //ICMP Protocol
          break;

      case 2:  //IGMP Protocol
          break;

      case 6:  //TCP Protocol
          printf_tcp_header(pktdata);
          break;

      case 17: //UDP Protocol
          break;

      default: //Some Other Protocol like ARP etc.
          break;
  }

}


int main (int argc, char* argv[]){
  int i , n , ret;//ret = return error chack value
  const u_char *packet;
  char *dev, devs[100][100];
  char *net; /* dot notation of the network address */
  char *mask;/* dot notation of the network mask    */
  bpf_u_int32 netp; /* ip          */
  bpf_u_int32 maskp;/* subnet mask */
/*
struct in_addr {
    in_addr_t s_addr; 32 u_int with network byte ordered
  };
*/
  struct in_addr addr;
  /*the error code buf of libpcap*/
  char ebuf[PCAP_ERRBUF_SIZE];
  /*create capture handler of libpcap*/
  pcap_t *indescr , *outdescr;
/*struct pcap_pkthdr {
  struct timeval ts; /* time stamp
  bpf_u_int32 caplen; /* length of portion present(current capture)
  bpf_u_int32 len; /* length this packet (off wire)
  };
*/
  struct pcap_pkthdr hdr;




  u_char *ptr;
  //get network interface name
  pcap_if_t *alldevsp , *device;
  printf("Finding available devices ... ");
  if( pcap_findalldevs( &alldevsp , ebuf) )
  {
      printf("Error finding devices : %s" , ebuf);
      exit(1);
  }
  printf("Done");

  //Print the available devices
  printf("\nAvailable Devices are :\n");
  int count = 1;
  for(device = alldevsp ; device != NULL ; device = device->next)
  {
      printf("%d. %s - %s\n" , count , device->name , device->description);
      if(device->name != NULL)
      {
          strcpy(devs[count] , device->name);
      }
      count++;
  }

  //printf("Enter the number of the device you want to sniff : ");
  //scanf("%d" , &n);
  dev = devs[1];
/* find network address and mask of the device
  // dev = pcap_lookupdev(ebuf);

  // if(dev == NULL){
  //   fprintf(stderr, "%s\n", ebuf);
  //   return 1;
  // }
  // printf("DEV: %s\n", dev);

  // ret = pcap_lookupnet(dev , &netp ,&maskp,ebuf);

  // if(ret == -1){
  //  fprintf(stderr,"%s\n",ebuf);
  //  return 1;
  // }

  addr.s_addr = netp;
  net = inet_ntoa(addr);

  if(net == NULL){
    fprintf(stderr,"inet_ntoa");
    return 1;
  }

  printf("NET: %s\n",net);

  addr.s_addr = maskp;
  mask = inet_ntoa(addr);

  if(mask == NULL){
    fprintf(stderr,"inet_ntoa");
    return 1;
  }

  printf("MASK: %s\n",mask);
*/
/* open the device for sniffing. pcap_open_live detail

       pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
       char *ebuf)

       snaplen - maximum size of packets to capture in bytes
       promisc - set card in promiscuous mode?
       to_ms   - time to wait for packets in miliseconds before read
       times out
       errbuf  - if something happens, place error string here

       Note if you change "prmisc" param to anything other than zero, you will
       get all packets your device sees, whether they are intendeed for you or
       not!! Be sure you know the rules of the network you are running on
       before you set your card in promiscuous mode!!
*/
  indescr = pcap_open_live(dev , MAX_PACKET_SIZE , Promiscuous , TIME_OUT , ebuf);

  if(indescr == NULL){
    fprintf(stderr,"pcap_open_live(): %s\n",ebuf);
    return 1;
  }
/*pcap_next detail
  u_char *pcap_next(pcap_t *p,struct pcap_pkthdr *h)
       so just pass in the descriptor we got from
       our call to pcap_open_live and an allocated
       struct pcap_pkthdr
*/

/*packet = pcap_next(indescr , &hdr);


  if(packet == NULL){
    fprintf(stderr, "Didn't grab packet\n");
    return 1;
  }
  printf("Packet %s\n" , packet);
  printf("Grabbed packet of length %d\n",hdr.len);
  printf("Recieved at ..... %s\n",ctime((const time_t*)&hdr.ts.tv_sec));
  printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

  ethptr = (struct ether_header *) packet;
  if (ntohs (ethptr->ether_type) == ETHERTYPE_IP){
      printf("Ethernet type hex:%x dec:%d is an IP packet\n",
              ntohs(ethptr->ether_type),
              ntohs(ethptr->ether_type));
  }
  else  if (ntohs (ethptr->ether_type) == ETHERTYPE_ARP){
      printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
              ntohs(ethptr->ether_type),
              ntohs(ethptr->ether_type));
  }
  else {
      fprintf(stderr,"Ethernet type %x not IP", ntohs(ethptr->ether_type));
      return 1;
  }
  i = ETHER_ADDR_LEN;
  ptr = ethptr->ether_dhost;
  printf(" Destination Address:  ");
  do{
      printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
  }while(--i>0);
  printf("\n");

  ptr = ethptr->ether_shost;
  i = ETHER_ADDR_LEN;
  printf(" Source Address:  ");
  do{
      printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
  }while(--i>0);
  printf("\n");
*/
/*pcap_next_ex
  struct pcap_pkthdr *pktheader;
  const u_char *pktdata;
  int res;

  while((res = pcap_next_ex( indescr, &pktheader, &pktdata)) == 1){
    struct iphdr* new_iph;
    struct in_addr new_daddr;
    u_char new_data[MAX_PACKET_SIZE];

    printf("pktheader length= %d\n" , pktheader->len);

    if(pktdata == NULL){
    fprintf(stderr, "Didn't grab packet\n");
    return 1;
    }
    printf("Grabbed packet of length %d\n",pktheader->len);
    printf("Recieved at ..... %s\n",ctime((const time_t*)&pktheader->ts.tv_sec));
    //printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

    ethptr = (struct ether_header *) pktdata;
    if (ntohs (ethptr->ether_type) == ETHERTYPE_IP){
        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(ethptr->ether_type),
                ntohs(ethptr->ether_type));
    }
    else  if (ntohs (ethptr->ether_type) == ETHERTYPE_ARP){
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(ethptr->ether_type),
                ntohs(ethptr->ether_type));
    }
    else {
        fprintf(stderr,"Ethernet type %x not IP", ntohs(ethptr->ether_type));
        return 1;
    }
    i = ETHER_ADDR_LEN;
    ptr = ethptr->ether_dhost;
    printf(" Destination MAC Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");

    ptr = ethptr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf(" Source MAC Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");

    if(pktheader->len > MAX_PACKET_SIZE) continue;

    memcpy(new_data, pktdata, pktheader->len);
    new_iph = (struct iphdr*) (new_data + sizeof(struct ethhdr));

    printf("Source IP = ");
    print_ip(ntohl(new_iph->saddr));
    printf("Destination IP = ");
    print_ip(ntohl(new_iph->daddr));

    printf("protocol = %d\n" , new_iph->protocol);



  }
*/
  //其中第一个参数是winpcap的句柄,第二个是指定捕获的数据包个数,如果为-1则无限循环捕获。第四个参数user是留给用户使用的。
  pcap_loop(indescr , -1 , process_packet , NULL);
  return 0;
}