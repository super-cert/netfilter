
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
int sexcheck = 1;
char urlstring[100];
struct ip_header{
  unsigned char version;
  unsigned char SerField[1];
  unsigned char length[2];
  unsigned char identification[2];
  unsigned char flag[2];
  unsigned char ttl[1];
  unsigned char proto[1];
  unsigned char headersum[2];
  unsigned char dstip[4];
  unsigned char srcip[4];
};
struct tcp_header{
  u_short src_port;
  u_short dst_port;
  unsigned char seqnum[4];
  unsigned char dstnum[4];
  u_char tcp_length;
  //#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  u_char flag;
  unsigned char windowsize[2];
  unsigned char checksum[2];
  unsigned char urgent_pointer[2];
};
void dump(unsigned char* buf, int size) 
{
    	
    int i;
    for (i = 0; i < size; i++) {
        //if (i % 16 == 0)
         //   printf("\n");
        printf("%02x ", buf[i]);
    }
 	printf("\n");
	printf("--------------------------------------------\n");
	printf("\n");
    for (i = 0; i < size; i++) {
	//if (i%16==0)
	  //  printf("\n");
	printf("%c ", buf[i]);
    }
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;
	
	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	
	struct ip_header *ip = (struct ip_header*)data;
	int iplength = (ip->version) & 0x0f;
	printf("version %d\n", (ip->version) >> 4);
	printf("length : %d\n", iplength*4);
	data += iplength*4;
	//dump(data,ret); // ret : size data : structure
	struct tcp_header *tcp = (struct tcp_header*)data;

	data+= ((tcp->tcp_length)>>4)*4;
	if (ret >= 0)
		printf("payload_len=%d ", ret);
	printf("\n");
	if(ret-iplength*4-((tcp->tcp_length)>>4)*4>=16)
	{
		char str1[50];
		
		memcpy(str1, data, 50);
		//printf("url : ");
		
		//printf("\n");	
		if(strstr(str1, urlstring)!=0)
		{
		printf("%s access detected!\n", urlstring);
		printf("url : %s", str1);
		sexcheck=1;
		}
		//printf("sex.com : ");
		
		}
	printf("\n");
	fputc('\n', stdout);
	
	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(sexcheck==1)
	{	sexcheck=0;
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char * argvdump = argv[2];
	memcpy(urlstring, argvdump,sizeof(urlstring));
	printf("%s\n", urlstring);
	
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}