#include <utils.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <protocol.h>
#include <string.h>


int read_pcap(const char *filename, int protocal, int start, int size, char **data, int *data_size) {

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap;
  struct pcap_pkthdr header;
  const unsigned char *packet;
  int data_space = 1000;

  *data_size = 0;
  *data = (char*) malloc(data_space * size);
  /*if (argc != 2) {
    fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
    return 1;
  }*/

  /* Open input PCAP file for reading */
  pcap = pcap_open_offline(filename, errbuf);
  if (pcap == NULL) {
    fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
    return 1;
  }

  while ((packet = pcap_next(pcap, &header)) != NULL) {
    struct sniff_ethernet *ethernet; /* The ethernet header */
    struct sniff_ip *ip;             /* The IP header */
    struct sniff_tcp *tcp;           /* The TCP header */
    struct sniff_udp *udp;

    unsigned int size_ip;
    unsigned int size_trans;

    if (*data_size + size > data_space){
      data_space += 500;
      char *temp_array = malloc(data_space * sizeof(char));
      memcpy(temp_array, *data, *data_size * sizeof(char));
      free(*data);
      *data = temp_array;
      free(temp_array);
    }
    ethernet = (struct sniff_ethernet *)(packet);
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
      printf("   * Invalid IP header length: %u bytes\n", size_ip);
      return 1;
    }
    if (protocal == IP){
      memcpy(*data + (*data_size), (unsigned char *)ip + start, size * sizeof(unsigned char));
      *data_size += size * sizeof(unsigned char);
      continue;
    }
    if (ip->ip_p == 6){ //protocal is UDP
      tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
      size_trans = TH_OFF(tcp) * 4;
      if (size_trans < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_trans);
        return 1;
      }
      if (protocal == TCP){
        memcpy(*data + (*data_size), (unsigned char *)tcp + start, size * sizeof(unsigned char));
        *data_size += size * sizeof(unsigned char);
        continue;
      }
    }
    else if (ip->ip_p == 17){ //protocal is UDP
      udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
      size_trans = SIZE_UDP;
      if (protocal == UDP){
        memcpy(*data + (*data_size), (unsigned char *)udp + start, size * sizeof(unsigned char));
        *data_size += size * sizeof(unsigned char);
        continue;
      }
    }
    unsigned char * rtp = ( unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_trans);
    if (protocal == RTP){
      memcpy(*data + (*data_size), (unsigned char *)rtp + start, size * sizeof(unsigned char));
      *data_size += size * sizeof(unsigned char);
      continue;
    }

    printf("Source IP: ");
    printf("%s\n", inet_ntoa(ip->ip_src));
    printf("Destination IP: ");
    printf("%s\n", inet_ntoa(ip->ip_dst));
  }

  /* Close the file */
  pcap_close(pcap);

  return 0;
}
