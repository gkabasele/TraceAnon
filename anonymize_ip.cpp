// Package: Crypto-PAn 1.0
// File: sample.cpp
// Last Update: April 17, 2002
// Author: Jinliang Fan

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/icmp.h>
#include <dirent.h>
#include <unistd.h>
#include <pcap.h>
#include <iostream>
#include <set>
#include <string>
#include <iterator>
#include "panonymizer.h"

#define IPPROTO_VRRP 112

using namespace std;

typedef struct pseudo_header{
	uint32_t src;
	uint32_t dst;
	uint8_t	 zero;
	uint8_t	 proto;
   uint16_t  len;	

} pseudo_header;

uint16_t ip_cksum(void *vdata, size_t len){
	char* data=(char*)vdata;
	uint32_t acc = 0xffff;

	for(size_t i=0;i+1<len;i+=2){
		uint16_t word;
		memcpy(&word, data+i, 2);
		acc += ntohs(word);
		if(acc > 0xffff){
			acc -= 0xffff;	
		}	
	}

	if(len&1){
		uint16_t word=0;
		memcpy(&word, data+len-1, 1);
		acc+=ntohs(word);
		if(acc>0xffff){
			acc -= 0xffff;	
		}	
	}

	return htons(~acc);
}

uint16_t transport_cksum(unsigned short *ptr, size_t len){
	long sum = 0;
	uint16_t oddbyte = 0;
	int16_t answer=0;

	while(len>1){
		sum +=*ptr++;
		len -= 2;	
	}

	if(len==1){
		oddbyte = 0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;	
		sum+=oddbyte;
	}

	sum = (sum>>16) + (sum & 0xffff);
	sum = sum + (sum>>16);
	answer =  (short)~sum;

	return answer;
}

u_int dotted_to_u_int(u_int b1, u_int b2, u_int b3, u_int b4){
	
	u_int raw_addr = (b1 << 24) + (b2 << 16) + (b3 << 8) + b4;
	return raw_addr;
}

void u_int_to_dotted(char (*addr)[INET_ADDRSTRLEN], u_int raw){

	
	u_int b1 = raw >> 24;
	u_int b2 = (raw << 8) >> 24; 
	u_int b3 = (raw << 16) >> 24;
	u_int b4 = (raw << 24) >> 24;

	snprintf(*addr, INET_ADDRSTRLEN, "%u.%u.%u.%u", b1, b2, b3, b4);
}




void loop_on_trace(char* input_file, char* output_file, struct pcap_pkthdr* header, const u_char *packet,
				   pcap_t *pcap_reader, pcap_t *pcap_writer, pcap_dumper_t *pdumper, PAnonymizer anonymizer,
				   set<string> *ips, set<u_int> ports , set<string> filter_ip, FILE* f) {
	
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_reader = pcap_open_offline(input_file, errbuf);
	if(pcap_reader == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", input_file, errbuf);	
		exit(EXIT_FAILURE);
	}

	printf("Opening input: %s, output: %s\n", input_file, output_file);
	pcap_writer = pcap_open_dead(DLT_EN10MB, 262144);
	if(pcap_writer == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", output_file, errbuf);
		exit(EXIT_FAILURE);	
	}

	pdumper = pcap_dump_open(pcap_writer, output_file);
	if(pdumper == NULL){
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", output_file, errbuf);	
		exit(EXIT_FAILURE);
	}

	struct ether_header* ethernet_hdr;
	struct ether_header* new_ethernet_hdr;
	struct ip* ip_hdr;
	struct icmphdr* icmp_hdr;
	struct tcphdr* tcp_hdr;
	struct udphdr* udp_hdr;
	char srcIP[INET_ADDRSTRLEN];
	char dstIP[INET_ADDRSTRLEN];
	char anon_srcIP[INET_ADDRSTRLEN];
	char anon_dstIP[INET_ADDRSTRLEN];
	u_int sourcePort, destPort;
	size_t index = 0;
	int out ;
	struct ip* new_ip_hdr;
	unsigned int anon_src_addr;
	unsigned int anon_dst_addr;
	bool keep = false;

	size_t len_header;
	size_t payload_size;

	set<string>::iterator it;
	set<u_int>::iterator port_it;
	set<string>::iterator ip_it;

	unsigned int identifier = 0;

	unsigned int pkt_addr1, pkt_addr2, pkt_addr3, pkt_addr4;


	while((out = pcap_next_ex(pcap_reader, &header, &packet)) == 1){

		index = 0;
		len_header = 0;
		ethernet_hdr = (struct ether_header*) packet;
		len_header += 14; // Ether header size

		index += sizeof(struct ether_header);

		if(ntohs(ethernet_hdr->ether_type) == ETHERTYPE_IP){
			ip_hdr = (struct ip*)(packet + index);
			index += sizeof(struct ip);

			inet_ntop(AF_INET, &(ip_hdr->ip_src), srcIP, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ip_hdr->ip_dst), dstIP, INET_ADDRSTRLEN);	

			string src = string(srcIP);
			string dst = string(dstIP);

			ip_it = filter_ip.find(src);
			keep = (ip_it == filter_ip.end());	
			if(keep){
				ip_it = filter_ip.find(dst);	
				keep = (ip_it == filter_ip.end()); 
			}

			if(!keep){
				continue;
			}

			len_header += (ip_hdr->ip_hl * 4);

			if(ip_hdr->ip_p == IPPROTO_ICMP){
				icmp_hdr = (struct icmphdr*)(packet + index);		
				index += sizeof(struct icmphdr);

				// ICMP : type (1byte) + code (1byte) + csum (2bytes) + (4bytes)
				len_header += 8;
				payload_size = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - 8;

				if((icmp_hdr->type == ICMP_TIMESTAMP || icmp_hdr->type == ICMP_TIMESTAMPREPLY)){
					continue;
				}
			}

			if(ip_hdr->ip_p == IPPROTO_TCP || ip_hdr->ip_p == IPPROTO_UDP){

				if(ip_hdr->ip_p == IPPROTO_TCP){
					tcp_hdr = (struct tcphdr*) (packet + index);
					index += sizeof(struct tcphdr);
					sourcePort = ntohs(tcp_hdr->source);
					destPort = ntohs(tcp_hdr->dest);

					len_header += tcp_hdr->doff * 4;
					payload_size = ntohs(ip_hdr->ip_len) - (tcp_hdr->doff*4) - (ip_hdr->ip_hl *4);
				}

				if(ip_hdr->ip_p == IPPROTO_UDP){
					udp_hdr = (struct udphdr*) (packet + index);
					index += sizeof(struct udphdr);
					sourcePort = ntohs(udp_hdr->source);
					destPort = ntohs(udp_hdr->dest);	
					// UDP Header size
					len_header += 8;
					payload_size = ntohs(udp_hdr->len) - 8;
				}

				port_it = ports.find(sourcePort);
				keep = (port_it == ports.end());

				if(keep){
					port_it = ports.find(destPort);	
					keep = (port_it == ports.end());
				}

				if(!keep){
					continue;	
				}
			}
			
			if(ip_hdr->ip_p == IPPROTO_VRRP){
				continue;
			}

			u_char *new_packet = (u_char*) malloc(header->len);
                                                                     
			if (new_packet == NULL){
				fprintf(stderr, "Could not allocate memory for the packet");	
				exit(EXIT_FAILURE);
			}
                                                                     
			memcpy(new_packet, packet, header->len);
			new_ethernet_hdr = (struct ether_header*) new_packet;

			// zerofying last 3 bytes to remove manufacturer code
			
			new_ethernet_hdr->ether_shost[0] = 0;
			new_ethernet_hdr->ether_shost[1] = 0;
			new_ethernet_hdr->ether_shost[2] = 0;
			
			new_ethernet_hdr->ether_dhost[0] = 0;
			new_ethernet_hdr->ether_dhost[1] = 0;
			new_ethernet_hdr->ether_dhost[2] = 0;

			new_ip_hdr = (struct ip*) (new_packet + sizeof(struct ether_header));

			// JUST ADDDED
			sscanf(srcIP, "%u.%u.%u.%u", &pkt_addr1, &pkt_addr2, &pkt_addr3, &pkt_addr4);	
			u_int raw_addr = dotted_to_u_int(pkt_addr1, pkt_addr2, pkt_addr3, pkt_addr4);

			anon_src_addr = anonymizer.anonymize(raw_addr);

			u_int_to_dotted(&anon_srcIP, anon_src_addr);

			sscanf(dstIP, "%u.%u.%u.%u", &pkt_addr1, &pkt_addr2, &pkt_addr3, &pkt_addr4);	
			raw_addr = dotted_to_u_int(pkt_addr1, pkt_addr2, pkt_addr3, pkt_addr4);

			anon_dst_addr = anonymizer.anonymize(raw_addr);

			u_int_to_dotted(&anon_dstIP, anon_dst_addr);

			inet_pton(AF_INET, anon_srcIP, &(new_ip_hdr->ip_src));
			inet_pton(AF_INET, anon_dstIP, &(new_ip_hdr->ip_dst));

			// END ADD


			//anon_src_addr = anonymizer.anonymize((ip_hdr->ip_src).s_addr);
			//anon_dst_addr = anonymizer.anonymize((ip_hdr->ip_dst).s_addr);
			//(new_ip_hdr->ip_src).s_addr = anon_src_addr;
			//(new_ip_hdr->ip_dst).s_addr = anon_dst_addr;
			


			memset(new_packet + index, 0, payload_size);	
			pcap_dump((u_char*) pdumper, header, new_packet);
			//inet_ntop(AF_INET, &(new_ip_hdr->ip_src), anon_srcIP, INET_ADDRSTRLEN);
			//inet_ntop(AF_INET, &(new_ip_hdr->ip_dst), anon_dstIP, INET_ADDRSTRLEN);	
			it = (*ips).find(src);	
			if(it == (*ips).end()){
				(*ips).insert(src);
				fprintf(f, "%s\t%s\n", srcIP, anon_srcIP);
			}
			
			it = (*ips).find(dst);
			if(it == (*ips).end()){
				(*ips).insert(dst);	
				fprintf(f, "%s\t%s\n", dstIP, anon_dstIP);
			}
			free(new_packet);
			
		}
		// Use only for debugging
		identifier += 1;

	}

	pcap_close(pcap_reader);
	pcap_close(pcap_writer);
	pcap_dump_close(pdumper);
}



int main(int argc, char * argv[]) {
    // Provide your own 256-bit key here
    unsigned char my_key[32] = 
	{24,39,33,151,32,204,7,118,4,22,1,32,73,147,105,86,
	 216,152,143,131,121,121,101,39,98,87,76,59,2,130,74,8};

	char *input_dir;
	char *output_dir;
	char *filename_mapping_ip;
	char *filename_port_filter;
	char *filename_ip_filter;
	int c;

	while((c = getopt(argc, argv, "i:o:m:p:f:")) != -1){
		switch(c){
			case 'i':
				input_dir = optarg;
				break;
			case 'o':
				output_dir = optarg;
				break;
			case 'm':	
				filename_mapping_ip  = optarg;
				break;
			case 'p':
				filename_port_filter = optarg;
				break;
			case 'f':
				filename_ip_filter = optarg;
				break;
			case '?':
				fprintf(stderr, "Unknown option");
				printf("Usage: anonymize_ip -i <name> -o <name> -m <name>\n");
				printf("-i: name of the directory containing the trace\n");
				printf("-o: name of the directory to output the trace\n");
				printf("-m: name of file to output the ip mapping\n");
				printf("-p: name of the file with the port to filter \n");
				printf("-f: name of the file with ip to filter \n");
				exit(EXIT_FAILURE);
			default:
				fprintf(stderr, "Unknown option");
				printf("Type ? to display help");
		}
	}


    FILE *f;
	FILE *filter_port_list;
	FILE *filter_ip_list;
	set<string> ips;
	set<u_int> ports; 
	set<string> filter_ips;

    PAnonymizer my_anonymizer(my_key);

	f = fopen(filename_mapping_ip, "w");

	if(f == NULL){
		fprintf(stderr, "Error opening the mapping file");	
		exit(EXIT_FAILURE);
	}

	filter_port_list = fopen(filename_port_filter, "r");

	if(filter_port_list == NULL){
		fprintf(stderr, "Error opening the port filter list");
		exit(EXIT_FAILURE);
	}

	filter_ip_list = fopen(filename_ip_filter, "r");

	if(filter_ip_list == NULL){
		fprintf(stderr, "Error opening the ip filter list");	
		exit(EXIT_FAILURE);
	}


	char* line_port = NULL;
	size_t len_port = 0;

	char* line_ip = NULL;
	size_t len_ip = 0;

	while((getline(&line_port, &len_port, filter_port_list)) != -1){
		u_int p = atoi(line_port);
		ports.insert(p);
	}

	ssize_t len = 0;
	char tmp[INET_ADDRSTRLEN];

	while((len = getline(&line_ip, &len_ip, filter_ip_list)) != -1){
		// Removing newline character
		memset(tmp, '\0', len);
		strncpy(tmp, line_ip, len-1);
		string s = string(tmp);	
		filter_ips.insert(s);
	}

	fclose(filter_port_list);
	fclose(filter_ip_list);
	if(line_port){
		free(line_port);	
	}
	if(line_ip){
		free(line_ip);	
	}

	int n;
	struct dirent **namedlist;

	// Reader
	pcap_t *pcap_handle = NULL;
	struct pcap_pkthdr header;
	const u_char *packet = NULL;

	// Writer
	pcap_t *pd = NULL;
	pcap_dumper_t *pdumper = NULL;

	n = scandir(input_dir, &namedlist, NULL, alphasort);
	if (n > 0){
		// . and .. discarded
		int i = 2;	
		char *fullname;
		char *outputname;
		fullname = (char*) malloc(strlen(input_dir) + strlen(namedlist[i]->d_name) + 2);
		outputname = (char*) malloc(strlen(output_dir) + strlen(namedlist[i]->d_name) + 2);

		if (fullname == NULL){
			fprintf(stderr, "Could not allocate memory for the fullname");	
			exit(EXIT_FAILURE);
		}
		
		if (outputname == NULL){
			fprintf(stderr, "Could not allocate memory for the outputname");	
			exit(EXIT_FAILURE);
		}

		fullname[0] = '\0';
		strncat(fullname, input_dir, strlen(input_dir));
		strncat(fullname, "/", 1);
		strncat(fullname, namedlist[i]->d_name, strlen(namedlist[i]->d_name));

		outputname[0] = '\0';
		strncat(outputname, output_dir, strlen(output_dir));
		strncat(outputname, "/", 1);
		strncat(outputname, namedlist[i]->d_name, strlen(namedlist[i]->d_name));

		while(i < n){
			memcpy(fullname + strlen(input_dir) + 1, namedlist[i]->d_name, strlen(namedlist[i]->d_name));	
			memcpy(outputname + strlen(input_dir) + 1, namedlist[i]->d_name, strlen(namedlist[i]->d_name));	
			loop_on_trace(fullname, outputname, &header, packet, pcap_handle,
						  pd, pdumper, my_anonymizer, &ips, ports, filter_ips, f);
			i++;
		}

		free(fullname);
		free(outputname);

	} else {
		fprintf(stderr, "Could not open directory: %s\n", input_dir);
		exit(EXIT_FAILURE);	
	}

	while(n--){
		free(namedlist[n]);	
	}

	free(namedlist);
	fclose(f);
	return 0;
	
}
