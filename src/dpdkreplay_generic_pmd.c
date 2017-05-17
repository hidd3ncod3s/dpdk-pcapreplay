
#include "dpdkreplay.h"
#include <unistd.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_ethdev.h>

#define FATAL_ERROR(fmt, args...)       rte_exit(EXIT_FAILURE, fmt "\n", ##args)

static void sig_handler(int sign)
{
	if (sign == SIGINT){
		printf("Stopping replay..\n");
		exit(0);
	}
}

/* allow max jumbo frame 9.5 KB */
#define	JUMBO_FRAME_MAX_SIZE	0x2600

int number_of_ports;

/*static const struct rte_eth_conf port_conf= {
	.rxmode= {ETH_MQ_RX_NONE},
	.txmode= {ETH_MQ_TX_NONE}
};*/

static const struct rte_eth_conf port_conf= {
        .rxmode= {
                        .mq_mode = ETH_MQ_RX_NONE,
                        //.jumbo_frame    = 1, /**< Jumbo Frame Support disabled */
                        //.max_rx_pkt_len = 9000, /* Jumbo frame max packet len */
                        //.max_rx_pkt_len = JUMBO_FRAME_MAX_SIZE, /* Jumbo frame max packet len */
                 },
        .txmode= {
                        .mq_mode = ETH_MQ_TX_NONE
                 }
};


#define MEMPOOL_NAME "dpdkpcapreplay_mem_pool"
//#define MEMPOOL_ELEM_SZ 2048
#define MEMPOOL_ELEM_SZ 9216
#define MEMPOOL_CACHE_SZ 512

//#define RX_QUEUE_SZ 256
#define RX_QUEUE_SZ 2048
#define TX_QUEUE_SZ 4096

static struct rte_mempool *pktmbuf_pool;

uint64_t buffer_size = 1048576/32; // Number of elements in the ring. 

/* Struct for configuring each rx queue. These are default values */             
static const struct rte_eth_rxconf rx_conf = {                                   
        .rx_thresh = {                                                           
                .pthresh = 8,   /* Ring prefetch threshold */                    
                .hthresh = 8,   /* Ring host threshold */                        
                .wthresh = 4,   /* Ring writeback threshold */                   
        },                                                                       
        .rx_free_thresh = 32,    /* Immediately free RX descriptors */           
};                                                                               
                                                                                 
/* Struct for configuring each tx queue. These are default values */             
static const struct rte_eth_txconf tx_conf = {                                   
        .tx_thresh = {                                                           
                .pthresh = 36,  /* Ring prefetch threshold */                    
                .hthresh = 0,   /* Ring host threshold */                        
                .wthresh = 0,   /* Ring writeback threshold */                   
        },                                                                       
        .tx_free_thresh = 0,    /* Use PMD default values */                     
        .txq_flags = ETH_TXQ_FLAGS_NOOFFLOADS | ETH_TXQ_FLAGS_NOMULTSEGS,  /* IMPORTANT for vmxnet3, otherwise it won't work */
        .tx_rs_thresh = 0,      /* Use PMD default values */                     
};  

void init_port(int port_id)
{
	struct rte_eth_dev_info dev_info;
	int ret;
	struct rte_eth_link link;
	
	rte_eth_dev_info_get(port_id, &dev_info);
	printf("Name:%s\n\tDriver name: %s\n\tMax rx queues: %d\n\tMax tx queues: %d\n", dev_info.pci_dev->driver->name,dev_info.driver_name, dev_info.max_rx_queues, dev_info.max_tx_queues);
	printf("\tPCI Adress: %04d:%02d:%02x:%01d\n", dev_info.pci_dev->addr.domain, dev_info.pci_dev->addr.bus, dev_info.pci_dev->addr.devid, dev_info.pci_dev->addr.function);

	ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
	if (ret < 0) 
		rte_panic("Error configuring the port\n");

	ret = rte_eth_rx_queue_setup(port_id, 0, RX_QUEUE_SZ, rte_socket_id(), &rx_conf, pktmbuf_pool);
	if (ret < 0) 
		FATAL_ERROR("Error configuring receiving queue= %d\n", ret);

	// TODO: Need to check whether it is supported in the VMXNET
	/*ret = rte_eth_dev_set_rx_queue_stats_mapping(port_id, 0, 0);       
	if (ret < 0) 
		FATAL_ERROR("Error configuring receiving queue stats= %d [ENOTSUP= %d]\n", ret, ENOTSUP); */

	ret = rte_eth_tx_queue_setup(port_id, 0, TX_QUEUE_SZ, rte_socket_id(), &tx_conf);
	if (ret < 0) 
		FATAL_ERROR("Error configuring transmitting queue. Errno: %d (%d bad arg, %d no mem)\n", -ret, EINVAL ,ENOMEM);

	/* Start device */    
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) 
		FATAL_ERROR("Cannot start port\n");

	/* Enable receipt in promiscuous mode for an Ethernet device */
	//rte_eth_promiscuous_enable(port_id);

	/* Print link status */
	rte_eth_link_get_nowait(port_id, &link);                
	if (link.link_status)   
		printf("\tPort %d Link Up - speed %u Mbps - %s\n", (uint8_t)port_id, (unsigned)link.link_speed,(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?("full-duplex") : ("half-duplex\n"));
	else
		printf("\tPort %d Link Down\n",(uint8_t)port_id);
}

//char * file_name = "/home/username/pcaps/test1.pcap";
char * file_name = "/home/username/pcaps/test.pcap";

struct pcap_hdr_t {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} ;

struct pcaprec_hdr_t {
   uint32_t ts_sec;         /* timestamp seconds */
   uint32_t ts_usec;        /* timestamp microseconds */
   uint32_t incl_len;       /* number of octets of packet saved in file */
   uint32_t orig_len;       /* actual length of packet */
} ;

uint64_t num_pkt_good_sent = 0;
uint64_t num_bytes_good_sent = 0;
uint64_t old_num_pkt_good_sent = 0;
uint64_t old_num_bytes_good_sent = 0;

struct timeval start_time;
struct timeval last_time;

#include <stdbool.h>
#include <rte_cycles.h>

bool do_shutdown = false;
int times=1;

void replay_packets()
{
	int ret;
	uint64_t tick_start;
	struct pcaprec_hdr_t hdr;
	struct rte_mbuf * m= NULL;
	FILE * file;

        /* Open the trace */
        printf("Opening file: %s\n", file_name);
        printf("Replay on %d interface(s)\n", number_of_ports);
        file = fopen(file_name, "r");
        if (file == NULL){
                printf("Unable to open file: %s\n", file_name);
                exit(1);
        }
        /* Prepare file pointer skiping pcap hdr, and setting large buffer */
        fseek(file, sizeof(struct pcap_hdr_t), SEEK_SET);
        ret = setvbuf(file, NULL, _IOFBF, 33554432);
        if (ret != 0) FATAL_ERROR("Cannot set the size of the file pointer to the trace...\n");

        /* Init start time */
        ret = gettimeofday(&start_time, NULL);
        if (ret != 0) FATAL_ERROR("Error: gettimeofday failed. Quitting...\n");
        last_time = start_time;
        tick_start =   rte_get_tsc_cycles();

        /* Start stats */
        alarm(1);

        /* Infinite loop */
        for (;;) {

                /* If the system is quitting, break the cycle */
                if (unlikely(do_shutdown))
                        break;

                /* Read packet from trace */
                ret = fread((void*)&hdr, sizeof (hdr), 1, file);
                if(unlikely(ret <= 0)) break;

                /* Alloc the buffer */
                m =  rte_pktmbuf_alloc  (pktmbuf_pool);

                /* Read data from trace */
                ret = fread((void*)((char*) m->buf_addr + m->data_off ), hdr.incl_len, 1 , file );
                if(unlikely(ret <= 0)) 
			break;
                /* Compile the buffer length */                
		m->data_len = m->pkt_len = hdr.incl_len;

		//while ( rte_eth_tx_burst (0/*port_id*/, 0, &m , 1) != 1)
		while ( vmxnet3_xmit_pkts(0/*port_id*/, 0, &m , 1) != 1)
			if (unlikely(do_shutdown)) 
				break;

		/* Update stats */                
		num_pkt_good_sent += times;                
		num_bytes_good_sent += (hdr.incl_len + 24) * times; /* 8 Preamble + 4 CRC + 12 IFG*/
	}

}

#define BURST_SIZE 2

void replay_packets_full()
{
	int ret;
	uint64_t tick_start;
	struct pcaprec_hdr_t *hdr;
	struct rte_mbuf * m= NULL;
	unsigned char *buffer=NULL;
	unsigned char *cur_buffer=NULL;
	unsigned char *endofbuffer=NULL;
	long fsize= 0;
	FILE * f= NULL;
	int bytes_read=0;
	struct rte_mbuf *tx_pkts[BURST_SIZE];
	int nb_pkts;
	int bytessent=0;

        /* Open the trace */
        printf("Opening file: %s\n", file_name);
        printf("Replay on %d interface(s)\n", number_of_ports);
        f = fopen(file_name, "r");
        if (f == NULL){
                printf("Unable to open file: %s\n", file_name);
                exit(1);
        }
	fseek(f, 0, SEEK_END);
	fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	buffer = malloc(fsize + 1);
	bytes_read= fread(buffer, fsize, 1, f);
	fclose(f);
	if (bytes_read == fsize){
		printf ("Read less than the original file size\n");
	}

        /* Prepare file pointer skiping pcap hdr, and setting large buffer */
        //fseek(file, sizeof(struct pcap_hdr_t), SEEK_SET);
        //ret = setvbuf(file, NULL, _IOFBF, 33554432);
        //if (ret != 0) FATAL_ERROR("Cannot set the size of the file pointer to the trace...\n");

        /* Init start time */
        ret = gettimeofday(&start_time, NULL);
        if (ret != 0) FATAL_ERROR("Error: gettimeofday failed. Quitting...\n");
        last_time = start_time;
        tick_start =   rte_get_tsc_cycles();

        /* Start stats */
        alarm(1);
	endofbuffer= buffer + fsize;

        /* Infinite loop */
        for (;;) {
                /* If the system is quitting, break the cycle */
                if (unlikely(do_shutdown)){
			printf("Stop sending packets...outer loop\n");
                       	break;
		}

		cur_buffer= buffer + sizeof(struct pcap_hdr_t);

		for (;;) {
                	/* If the system is quitting, break the cycle */
                	if (unlikely(do_shutdown))
                        	break;

                	/* Read packet from trace */
                	//ret = fread((void*)&hdr, sizeof (hdr), 1, file);
                	//if(unlikely(ret <= 0)) break;
			nb_pkts= 0;
			bytessent=0;
			for (; nb_pkts < BURST_SIZE; ){
				if ((cur_buffer + sizeof(struct pcaprec_hdr_t)) >= endofbuffer){
					//printf("Reached end of buffer while reading the header\n");
					break;
				}
				hdr=  (struct pcaprec_hdr_t*) cur_buffer;
				if ((cur_buffer + hdr->incl_len) > endofbuffer){
					//printf("Reached end of buffer while reading the packet\n");
					break;
				}

				cur_buffer += sizeof(struct pcaprec_hdr_t);
				//printf("adding a packet\n");

                		/* Alloc the buffer */
                		m =  rte_pktmbuf_alloc  (pktmbuf_pool);
				//memcpy(((char*) m->buf_addr + m->data_off ), cur_buffer, hdr->incl_len);
				rte_memcpy(((char*) m->buf_addr + m->data_off ), cur_buffer, hdr->incl_len);
                		/* Compile the buffer length */                
				m->data_len = m->pkt_len = hdr->incl_len;
				tx_pkts[nb_pkts++]= m;
				cur_buffer += hdr->incl_len;
				bytessent += (hdr->incl_len + 24) * times;
			}
			//printf("try sending %d packets\n", nb_pkts);

			//while ( rte_eth_tx_burst (0/*port_id*/, 0, &tx_pkts , nb_pkts) != 1)
			if (nb_pkts > 0){
				//rte_eth_tx_burst (0/*port_id*/, 0, &tx_pkts[0] , nb_pkts);
				while ( rte_eth_tx_burst (0/*port_id*/, 0, &tx_pkts[0] , nb_pkts) != nb_pkts)
				if (unlikely(do_shutdown)){ 
					printf("Stop sending packets while on transmit...\n");
					break;
				}
			}

			if (unlikely(do_shutdown)){ 
				printf("Stop sending packets...\n");
				break;
			}

			/* Update stats */                
			num_pkt_good_sent += (nb_pkts * times);
			num_bytes_good_sent += bytessent; /* 8 Preamble + 4 CRC + 12 IFG*/
			if (nb_pkts < BURST_SIZE){
				//printf("Read less than %d packets\n", nb_pkts);
				break;
			}
		}
		//printf("next round\n");
	}

}

void print_stats (void){
        int ret;
        struct timeval now_time;
        double delta_ms;
        double tot_ms;
        double gbps_inst, gbps_tot, mpps_inst, mpps_tot;

        /* Get actual time */
        ret = gettimeofday(&now_time, NULL);
        if (ret != 0) FATAL_ERROR("Error: gettimeofday failed. Quitting...\n");

        /* Compute stats */
        delta_ms =  (now_time.tv_sec - last_time.tv_sec ) * 1000 + (now_time.tv_usec - last_time.tv_usec ) / 1000 ;
        tot_ms = (now_time.tv_sec - start_time.tv_sec ) * 1000 + (now_time.tv_usec - start_time.tv_usec ) / 1000 ;
        gbps_inst = (double)(num_bytes_good_sent - old_num_bytes_good_sent)/delta_ms/1000000*8;
        gbps_tot = (double)(num_bytes_good_sent)/tot_ms/1000000*8;
        mpps_inst = (double)(num_pkt_good_sent - old_num_pkt_good_sent)/delta_ms/1000;
        mpps_tot = (double)(num_pkt_good_sent)/tot_ms/1000;

        printf("Rate: %8.3fGbps  %8.3fMpps [Average rate: %8.3fGbps  %8.3fMpps], Buffer: %8.3f%%\n", gbps_inst, mpps_inst, gbps_tot, mpps_tot, (double)rte_mempool_free_count (pktmbuf_pool)/buffer_size*100.0);

        /* Update counters */
        old_num_bytes_good_sent = num_bytes_good_sent;
        old_num_pkt_good_sent = num_pkt_good_sent;
        last_time = now_time;

}

void alarm_routine (__attribute__((unused)) int unused){

        /* If the program is quitting don't print anymore */
        if(do_shutdown) return;

        /* Print per port stats */
        print_stats();

        /* Schedule an other print */
        alarm(1);
        signal(SIGALRM, alarm_routine);

}

static int parse_args(int argc, char **argv)
{
	int option;
	

	/* Retrive arguments */
	while ((option = getopt(argc, argv,"f:s:r:B:C:t:T:")) != -1) {
        	switch (option) {
             		case 'f' : file_name = strdup(optarg); /* File name, mandatory */
                 		break;
             		default: return -1; 
		}
   	}

	return 0;
}


int main(int argc, char **argv)
{
	int ret;
	int i;

	signal(SIGINT, sig_handler);
	signal(SIGALRM, alarm_routine);

	ret= rte_eal_init(argc, argv);
	if (ret < 0)
		FATAL_ERROR("Error in initializing EAL\n");

	argc -= ret;
	argv += ret;

	parse_args(argc, argv);

	ret= rte_lcore_count();
	if (ret != 1)
		FATAL_ERROR("This application needs one lcore. Has= %d\n", ret);


	number_of_ports= rte_eth_dev_count();
	if (number_of_ports != 1)
		FATAL_ERROR("This application needs one eth interface. Has= %d\n", number_of_ports);

	
	pktmbuf_pool = rte_mempool_create(MEMPOOL_NAME, buffer_size-1, MEMPOOL_ELEM_SZ, MEMPOOL_CACHE_SZ, sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL,rte_socket_id(), 0);
	if (pktmbuf_pool == NULL) 
		FATAL_ERROR("Cannot create mem_pool. Errno: %d [ENOMEM: %d, ENOSPC: %d, E_RTE_NO_CONFIG: %d, E_RTE_SECONDARY: %d, EINVAL: %d, EEXIST: %d]\n", rte_errno, ENOMEM, ENOSPC, E_RTE_NO_CONFIG, E_RTE_SECONDARY, EINVAL, EEXIST  );


	for(i=0; i < number_of_ports; i++)
		init_port(i);

	//replay_packets();
	replay_packets_full();

	return ret;
}
