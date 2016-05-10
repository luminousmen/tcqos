
#include <net/tcp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <linux/inet.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/hashtable.h>
#include <linux/netfilter_ipv4.h>

#define HASHSIZE 20
#define RWND_MAX 30000000

/* timer for recalculating in nanoseconds */
uint64_t time = 40000000;
uint32_t timer_rwnd = 0;//200000000;
uint32_t change = 0;

/* admin's speed */
uint32_t default_speed = 1000000;//b/sec
int addition_value = 200000;
/* needed structures */

static struct nf_hook_ops nfho;//net filter hook option struct
struct sk_buff *sock_buff;
struct tcphdr *tcp_header;//udp header struct (not used)
struct iphdr *ip_header;//ip header struct

typedef struct{
	uint32_t time_rwnd;
	uint32_t speed;
	uint16_t dest_port;
	uint16_t source_port;
	uint32_t dest_ip;
	uint32_t source_ip;
	uint32_t mss;
	uint32_t flag;
	/*timer for calculate BE*/
	uint64_t timer;

	/*timer*/
	uint64_t last_time;
	/*smoothed bandwidth estimate in bytes/sec */
	uint64_t sbe;
	uint64_t bytes;	
	/*last ack in bytes*/
	uint64_t last_ack;
	/*smoothed congestion window*/
	uint64_t cwnd;
	/*receive window*/
	uint64_t rwnd;

	uint32_t wnd_scale;
	struct hlist_node my_list;
} connection;

typedef struct {
	unsigned char kind;
	unsigned char size;
} tcp_option_t;

typedef struct{
    unsigned int data : 24;
} integer24;

DEFINE_HASHTABLE(storage, HASHSIZE);

void calculate_cwnd(uint32_t ack_seq, connection* found) {	
	/* calculate cwnd in bytes */
	uint64_t ack_diff = (ack_seq - found->bytes);
	found->bytes = ack_seq;
	uint64_t cwindow = found->cwnd;
	do_div(ack_diff, 10);
	do_div(cwindow, 10);
	found->cwnd = 5 * cwindow + 5 * ack_diff;
}

void calculate_rwnd(connection * found, uint32_t window){
	/* calculate rwnd */
	uint64_t be = found->sbe;//in b/sec
	printk(KERN_INFO "wind=%d", window);
	if(be > found->speed){
		printk(KERN_INFO "Stage 1\n");
		be *= 1000;
		do_div(be, found->speed);//be = be/speed

		uint64_t rwnd = found->cwnd * 100000 * 1000;
		do_div(rwnd , be);

		/*limit expand*/
		if(rwnd  > 100000)
			do_div(rwnd, 100000);
		else rwnd = 1;

		do_div(rwnd, 10);
		do_div(found->rwnd, 10);
		found->rwnd = 2 * found->rwnd + 8 * rwnd;
	}
	else {
		printk(KERN_INFO "Stage 2\n");
		
		uint64_t new_speed = found->speed * 1000;
		if(be == 0)
			be = 1;
				
		do_div(new_speed, be);//new_speed = new_speed/be

		uint64_t rwnd = found->cwnd * new_speed; // rwnd = cwnd * N

		//rwnd = (rwnd > RWND_MAX)?RWND_MAX:rwnd;
		if(rwnd  > 1000)
			do_div(rwnd, 1000);
		else rwnd = 1;

		do_div(rwnd, 10);
		do_div(found->rwnd, 10);
		found->rwnd = 5 * found->rwnd + 5 * rwnd;
	}
}

void calculate_sbe(connection* found, uint64_t bytes_diff, uint64_t time_diff){
	if(time_diff > 1000000){//1000000
		do_div(time_diff, 1000000);
	}
	else time_diff = 1;
	/* bandwidth estimate in b/nsec */
	do_div(bytes_diff, time_diff);
	printk(KERN_INFO "current_be=%lld\n", bytes_diff);
	
	if(found->sbe == 0)
		found->sbe = bytes_diff;//sbe = be
	else{
		if(found->sbe > 10)
			do_div(found->sbe, 10);
		else found->sbe = 1;
		if(bytes_diff > 10)
			do_div(bytes_diff, 10);
		else bytes_diff = 1;
		found->sbe =  5 * found->sbe + 5 * bytes_diff;//in b/sec
	}
}

int hash_key(uint16_t dest_port, uint16_t source_port, unsigned int dest_ip, unsigned int source_ip){
	/* STRANGE CONVERT */
	char a[12];
	char* b = &a[0];
	int* c = (int*)b;
	c[0] = dest_port; c[1] = source_port;
	short* d = (short*)(b + 8);
	d[0] = dest_ip;	d[1] = source_ip;
	/* END */
	int key = jhash(b,12,0);
	return key;
}

connection* find_in_hash(uint16_t dest_port, uint16_t source_port, unsigned int dest_ip, unsigned int source_ip){
	int key = hash_key(dest_port, source_port,dest_ip, source_ip);

	connection* current_connection;
	hash_for_each_possible_rcu(storage, current_connection, my_list, key){
		if(current_connection->dest_port == dest_port && 
			current_connection->source_port == source_port &&
			current_connection->dest_ip == dest_ip &&
			current_connection->source_ip == source_ip){
			return current_connection;
		}
	}
	return NULL;
}

unsigned int inet_addr(char *str){
	int a,b,c,d;
	char arr[4];
	sscanf(str, "%d.%d.%d.%d", &a,&b,&c,&d);
	arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
	return *(unsigned int*)arr;
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	if(skb_is_nonlinear(skb))
		skb_linearize(skb);
		sock_buff = skb;

		ip_header = (struct iphdr *)skb_network_header(sock_buff);    //grab network header using accessor

		if(!sock_buff) { 
			return NF_ACCEPT;
		}

		if (ip_header->protocol == IPPROTO_TCP) {
			tcp_header = (struct tcphdr *)skb_transport_header(sock_buff);  //grab transport header
		if(tcp_header->ack == 1 && tcp_header->syn != 1){
			/* ack packet from client */
			connection* found = find_in_hash(tcp_header->dest, 
				tcp_header->source, 
				ip_header->daddr,
				ip_header->saddr);

			if(found != NULL && found->flag > 0){
				/* calculate cwnd */
				calculate_cwnd(ntohl(tcp_header->ack_seq), found);
				// if(found->rwnd)
				// found->cwnd = found->rwnd;

				/* change rwnd in ACK packet */
				uint64_t rwnd_to_packet = found->rwnd ;//32
				do_div(rwnd_to_packet, found->wnd_scale);
				uint32_t rwnd_new = rwnd_to_packet;
				tcp_header->window = htons(rwnd_new);

				/* tcplen is the length of the skb - the ip-header length */
				int tcplen = (skb->len - (ip_header->ihl << 2));

				tcp_header->check = 0;
				tcp_header->check = tcp_v4_check(tcplen,
					ip_header->saddr,ip_header->daddr,
					csum_partial((char*) tcp_header, tcplen, 0));

				skb->ip_summed = CHECKSUM_NONE;/* in case another hardware has TCP offloading */
			}

			if(found != NULL && (ktime_to_ns(ktime_get()) - found->last_time) >= time && found->flag > 0){//flag try
				found->last_time =  ktime_to_ns(ktime_get());
				/* time in nanosec */
				uint64_t time_diff = found->last_time - found->timer;
				/* write to structure */
				found->timer = found->last_time;
				/* time in mickrosec */
				//do_div(time_diff, 1000000);	

				/* multiply by 1000 to get more digits */
				uint64_t bytes_diff = (ntohl(tcp_header->ack_seq) - found->last_ack) * 1000;
				printk(KERN_INFO "bytes_diff = %lld", bytes_diff);					
				found->last_ack = ntohl(tcp_header->ack_seq);

				/* calculate smoothed bandwidth estimation */
				calculate_sbe(found, bytes_diff, time_diff);

				if (ktime_to_ns(ktime_get()) - found->time_rwnd > timer_rwnd){
					/* calculate rwnd */
					calculate_rwnd(found, ntohl(tcp_header->window)<<found->wnd_scale);
					found->time_rwnd = ktime_to_ns(ktime_get());
				}
				/* print all stuff */	
				printk(KERN_INFO "last_ack=%lld\n", found->last_ack);			
				printk(KERN_INFO "sbe=%lld\n", found->sbe);
				printk(KERN_INFO "rwnd_count=%lld\n", found->rwnd);
				printk(KERN_INFO "cwnd=%lld\n", found->cwnd);
			}
			else if(found != NULL && found->flag < 1){
				found->last_time =  ktime_to_ns(ktime_get());
				found->last_ack = found->bytes = ntohl(tcp_header->ack_seq) - 100;	
				found->flag = 1;
			}
		}
		/* end */
		
		if(tcp_header->syn == 1 && tcp_header->ack != 1){

			connection* found = find_in_hash(tcp_header->dest, 
				tcp_header->source, 
				ip_header->daddr,
				ip_header->saddr);

			if(found == NULL){
				connection* f = kmalloc(sizeof(connection), GFP_KERNEL);
				/* store all connections in hashtable */			
				f->dest_port = tcp_header->dest;
				f->source_port = tcp_header->source;
				f->dest_ip = ip_header->daddr;
				f->source_ip = ip_header->saddr;
				/* Initialize */
				f->flag = 0;
				f->timer = f->last_time = f->bytes = f->sbe = f->last_ack = f->rwnd = f->cwnd = 0;
				
				f->speed = default_speed + addition_value;
		
				/* calculate hash key to store in hashtable */
				int key = hash_key(f->dest_port, f->source_port, 
					f->dest_ip, f->source_ip);

				unsigned char* tmp = tcp_header;
				if (tcp_header->doff > 5) {
					unsigned char* opt = tmp + sizeof(struct tcphdr);
				 	while( *opt != 0 ) {
						tcp_option_t* _opt = (tcp_option_t *)opt;
						if( _opt->kind == 1 ) { //NOP
							++opt;  // NOP is one byte;
							continue;
						}
						if( _opt->kind == 2 ) {
							/* MSS */
							unsigned int* mss_opt = (unsigned int *)(opt + sizeof(tcp_option_t));
							unsigned int mss = htons(*mss_opt);
							f->mss = mss;
						}
						if( _opt->kind == 3 ) {
							/* wnd_scale> */
							integer24* wnd_opt = (integer24*)(opt + sizeof(tcp_option_t));
							integer24 wnd_scale = *wnd_opt;
							f->wnd_scale = wnd_scale.data;
							f->wnd_scale = 2 << (f->wnd_scale - 1);
						}
						opt += _opt->size;
				
						if (_opt->size == 0) {
							//pr_info("Very strange situation: zero size\n");
							break;
						}		
					}
				}
				/* add to hashtable */			
				hash_add(storage, &f->my_list, key);
			}
		}
			return NF_ACCEPT;
	}
	return NF_ACCEPT;
}

int init_module(void) {
	pr_info("Starting module...\n");
	hash_init(storage);
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_FORWARD;
	nfho.pf = AF_INET;
	nfho.priority = NF_IP_PRI_FIRST; 
	nf_register_hook(&nfho);
	return 0;
}

void cleanup_module(void){
	pr_info("Cleaning up...\n");
	nf_unregister_hook(&nfho);
}

MODULE_AUTHOR("Bobrov Kirill");
MODULE_DESCRIPTION("Window-sizing method in regulating speed rate");
MODULE_LICENSE("GPL");