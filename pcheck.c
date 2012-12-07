#include <stdio.h>
#include <pcap.h>



int main(int argc, char **argv) {
  char *device_name = argv[1];
  printf("Device: %s\n", device_name);
  char filter_exp[] = "";
  char errbuf[PCAP_ERRBUF_SIZE];
  
  pcap_t *handle = pcap_open_live(device_name, BUFSIZ, 0, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", device_name, errbuf);
    return(2);
  }

  struct bpf_program filter;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct pcap_pkthdr header;
  struct bpf_program fp;
  
  if (pcap_lookupnet(device_name, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device_name, errbuf);
    net = 0;
    mask = 0;
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }
  
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }

  const u_char *packet = pcap_next(handle, &header);


  printf("Packet captured with length %u.\n", header.len);
  
  int i;
  u_char charp;
  for (i=0; i<header.len; i++) {
    if (packet == NULL) break;
    if (packet[i] < ' ' || packet[i] > '~') {
      charp = '.';      
    } else {
      charp = packet[i];
    }
    printf("%c", charp);
    if (i % 16 == 0) {
      printf("\n");
    }
  }
  printf("\n");
  

  pcap_close(handle);
  
  return(0);
}

