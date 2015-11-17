#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
void printer(){
  printf("A packet is captured!\n");
  return;
}

int main (int argc, char* argv[]){
  int i;
  char *dev;
  /*the error code buf of libpcap*/
  char ebuf[PCAP_ERRBUF_SIZE];
  /*create capture handler of libpcap*/
  pcap_t* descr;
  const u_char *packet;
  struct pcap_pkthdr hdr;
  struct ether_header *ethptr;

  u_char *ptr;

  dev = pcap_lookupdev(ebuf);

  if(dev == NULL){
    printf("%s\n", ebuf);
    exit(1);
  }
  printf("DEV: %s\n", dev);
  return 0;
}