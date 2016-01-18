#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/types.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static int Callback(struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data *, void *);
uint16_t tcp_checksum_calc(uint32_t saddr, uint32_t daddr, uint16_t tcp_len, uint8_t buff[]);
int isprint(int c);
#ifdef __DEBUG
void display_data(const unsigned char *, int, int);
#endif

int queue_num = -1;
char role = 's';
int packet_count = 0;

int main(int argc, char **argv) {
	int ch;
	
	while((ch = getopt(argc, argv, "n:r:h")) != -1){
		switch(ch){
			case 'h':
				printf("usage: -h              show this message;\n");
				printf("       -n QUEUE_NUM    specify the queue num to bind to. default is 0.\n");
				exit(0);
			case 'n':
				sscanf(optarg, "%d", &queue_num);
				printf("get command line option: -%c %d\n", ch, queue_num);
				if(queue_num < 0){
					printf("invalid option value: -%c %d\n", ch, queue_num);
					exit(1);
				}
				break;
			case 'r':
				sscanf(optarg, "%c", &role);
				printf("get command line option: -%c %c\n", ch, role);
				if(role != 's' && role != 'c'){
					printf("invalid option value: -%c %c\n", ch, role);
					exit(1);
				}
				break;
			default:
				printf("unknown option: %c. use -h to see usage.\n", ch);
				exit(1);
		}
	}
	
	struct nfq_handle *nfqHandle;
	
	struct nfq_q_handle *myQueue;
	
	int fd, res;
	char buf[4096];
	
	// Get a queue connection handle from the module
	if (!(nfqHandle = nfq_open())) {
		printf("Error in nfq_open()\n");
		exit(-1);
	}
	
	// Unbind the handler from processing any IP packets
	// Not totally sure why this is done, or if it's necessary...
	if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
		printf("Error in nfq_unbind_pf()\n");
		exit(1);
	}
	
	// Bind this handler to process IP packets...
	if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
		printf("Error in nfq_bind_pf()\n");
		exit(1);
	}
	
	// Install a callback on queue queue_num
	if (!(myQueue = nfq_create_queue(nfqHandle, queue_num, &Callback, NULL))) {
		printf("Error in nfq_create_queue()\n");
		exit(1);
	}

	
	// Turn on packet copy mode
	if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) {
		printf("Could not set packet copy mode\n");
		exit(1);
	}
	
	fd = nfq_fd(nfqHandle);
	
	while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
		nfq_handle_packet(nfqHandle, buf, res);
	}
	
	nfq_destroy_queue(myQueue);
	
	nfq_close(nfqHandle);
	
	return 0;

}

static int Callback(struct nfq_q_handle *myQueue, struct nfgenmsg *msg, struct nfq_data *pkt, void *cbData) {
	uint32_t id;
    struct nfqnl_msg_packet_hdr *header;
	header = nfq_get_msg_packet_hdr(pkt);
	id = ntohl(header->packet_id);
	unsigned char *pktData;
	int  i;
	int len = nfq_get_payload(pkt, &pktData);
	
	#ifdef __DEBUG
	printf("=== incoming packet #%d ===\n", packet_count++);
	if (len) {
		printf("before altering: data[%d]: \n", len);
		display_data(pktData, len, 8);
		printf("\n");
	}
	#endif
	
	struct iphdr *ip_header = (struct iphdr*)pktData;
	uint16_t ip_payload_len = len - ip_header->ihl * 4;
	unsigned char *ip_payload = pktData + ip_header->ihl * 4;
	
	struct tcphdr *tcp_header = (struct tcphdr*)ip_payload;
	
	unsigned char *tcp_payload = ip_payload + ((uint8_t)(tcp_header->doff)) * 4;
	uint16_t tcp_payload_len = ip_payload_len - ((uint16_t)(tcp_header->doff)) * 4;
	
	if(tcp_payload_len){
		for( i = 0; i < tcp_payload_len; i++){
			*(tcp_payload + i) = ~*(tcp_payload + i);
		}
		tcp_header->check = 0; //set tcp header checksum to 0

		tcp_header->check = htons(tcp_checksum_calc(ntohl(ip_header->saddr), ntohl(ip_header->daddr), ip_payload_len, (uint8_t *)ip_payload));
		#ifdef __DEBUG
		printf("after altering: data[%d]: \n", len);
		display_data(pktData, len, 8);
		printf("\n");
		#endif
	}else{
		#ifdef __DEBUG
		printf("Did not change packet\n");
		#endif
	}
	return nfq_set_verdict(myQueue, id, NF_ACCEPT, len, pktData);
	
}
uint16_t tcp_checksum_calc(uint32_t saddr, uint32_t daddr, uint16_t tcp_len, uint8_t buff[]){
	//printf("calculating checksum...\n");
	uint16_t psd_header[6] = {
		*((uint16_t *)&saddr + 1),
		(uint16_t)(saddr & 0x0000FFFF),
		*((uint16_t *)&daddr + 1),
		(uint16_t)(daddr & 0x0000FFFF),
		0x0006,
		tcp_len
	};
	
	//printf("saddr: %08x, daddr: %08x\n", saddr, daddr);
	int i = 0;
	for(; i < 6; i++){
		//printf("psd_header[%d]: %04hx\n", i, psd_header[i]);
	}
	uint32_t sum = 0;
	uint16_t word16 = 0;
	//printf("adding pseudo headers...\n");
	for(i = 0; i < 6; i++){
		sum += psd_header[i];
		//printf("sum = %08x\n", sum);
	}
	//printf("adding tcp data...\n");
	for( i = 0; i < tcp_len - 2; i += 2){
		//printf("((uint16_t)buff[%d]) << 8: %04hx\n", i, ((uint16_t)buff[i]) << 8);
		//printf("(uint16_t)buff[%d]: %04hx\n", i+1, (uint16_t)buff[i+1]);
		word16 = ((uint16_t)buff[i]) << 8; 
		word16 += (uint16_t)buff[i+1];
		//printf("buff[%d]: %02hhx, buff[%d]: %02hhx, word16: %04hx\n", i,  buff[i], i+1, buff[i+1], word16);
		sum += word16;
		//printf("sum = %08x\n", sum);
	}
	
	if( tcp_len & 1 ){
		//printf("dealing with odd packet length...\n");
		//printf("(buff[tcp_len - 1]) is %02hhx\n", buff[tcp_len - 1]);
		word16 = ((uint16_t)(buff[tcp_len - 1])) << 8;
		//printf("((uint16_t)(buff[tcp_len - 1])) << 8 is %04hx\n", word16);
		sum += word16;
		//printf("sum = %08x\n", sum);
	}else{
		//printf("dealing with even packet length...\n");
		word16 = *((uint16_t *)(buff + tcp_len - 2)) << 8;
		word16 += (uint16_t)(buff[tcp_len - 1]);
		//printf("operant: %04hx\n", word16);
		sum += word16;
		//printf("sum = %08x\n", sum);
	}
	while(sum >> 16)
		sum = (sum >> 16) + (sum & 0x0000FFFF);
	//printf("after chopping off carries: %04hx\n", sum);
	sum = ~ sum;
	//printf("inverted sum: %08x", sum);
	
	return (uint16_t)sum & 0xFFFF;
}

#ifdef __DEBUG
void display_data(const unsigned char *data, int data_len, int max_col){
	int i = 0; int k = 0;
	int j;
	while(i < data_len && k < data_len){
		for (j = 0; (j < max_col) &&(i < data_len); j++, i++){
			printf("%02hhx ", (const char)data[i]);
		}
		printf("    ");
		for (j = 0; (j < max_col) && (k < data_len); j++, k++){
			if(isprint((const char)data[k]))
				printf("%c", (const char)data[k]);
			else
				printf(" ");
		}
		printf("\n");
	}
}
#endif

