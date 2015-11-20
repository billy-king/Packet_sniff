#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <pcap.h>
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define MAX_PACKET_SIZE 256 //bytes
#define Promiscuous 1
#define TIME_OUT 1 //ms

int main (int argc, char* argv[]){
  int i , ret;//ret = return error chack value
  const u_char *packet;
  char *dev;
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
  };*/
  struct pcap_pkthdr hdr;

  struct ether_header *ethptr;

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

  u_char *ptr;
  //get network interface name
  dev = pcap_lookupdev(ebuf);

  if(dev == NULL){
    fprintf(stderr, "%s\n", ebuf);
    return 1;
  }
  printf("DEV: %s\n", dev);

  ret = pcap_lookupnet(dev , &netp ,&maskp,ebuf);

  if(ret == -1){
   fprintf(stderr,"%s\n",ebuf);
   return 1;
  }

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

  /* open the device for sniffing.

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
       before you set your card in promiscuous mode!!     */
  indescr = pcap_open_live(dev , MAX_PACKET_SIZE , Promiscuous , TIME_OUT , ebuf);

  if(indescr == NULL){
    fprintf(stderr,"pcap_open_live(): %s\n",ebuf);
    return 1;
  }
  /*
  u_char *pcap_next(pcap_t *p,struct pcap_pkthdr *h)
       so just pass in the descriptor we got from
       our call to pcap_open_live and an allocated
       struct pcap_pkthdr
  */

  packet = pcap_next(indescr , &hdr);


  if(packet == NULL){
    fprintf(stderr, "Didn't grab packet\n");
    return 1;
  }

  printf("Grabbed packet of length %d\n",hdr.len);
  printf("Recieved at ..... %s\n",ctime((const time_t*)&hdr.ts.tv_sec));



  return 0;
}