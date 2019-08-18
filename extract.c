//Header
#include <stdio.h> //fungsi fprintf, fopen, fclose, printf
#include <pcap.h> //fungsi pcap_loop,pcap_close,pcap_open_offline
#include <string.h> //fungsi strcpy
#include <stdlib.h> //fungsi exit
#include <unistd.h> //fungsi getopt,optarg
#include <ctype.h> //fungsi isprint
#include <netinet/tcp.h> //struct tcphdr
#include <netinet/udp.h> //struct udphdr
#include <netinet/ip.h> //struct iphdr
#include <netinet/ip_icmp.h> //struct icmphdr
#include <arpa/inet.h> // fungsi inet_ntoa, ntohs, ntohl
#include <net/ethernet.h> //struct ether_header
#include <time.h>
//end header

//Definisi warna berbentuk makro
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define RESET "\x1B[0m"
//end definisi warna

int jumlah_packet; //global variabel
FILE *file_csv; //global variabel
char *kosong="-"; //global variabel
char *warn_pay = "Payload tidak di cetak to big";
void timestamp_to_readable(struct timeval waktu){ //fungsi pemrosesan epoch time dan time
	char buf[255];
	char time_stamp_buff[255];
	sprintf(time_stamp_buff,"%d.%06d",(int) waktu.tv_sec, (int) waktu.tv_usec);
	struct tm *waktu_s;
	time_t convert_waktu;
	convert_waktu = waktu.tv_sec;
	waktu_s = localtime(&convert_waktu);
	strftime(buf, sizeof(buf), "%c", waktu_s);
	fprintf(file_csv,"%s, %s,",buf,time_stamp_buff);
}

void print_payload(const struct pcap_pkthdr *pkthdr,const u_char *packet){ //prosedur pemrosesan payload dari paket
	int i;
	int pjg = pkthdr->len;
	for(i=0;i<pjg;i++) { //loop yang akan terus berulang hingga i sama dengan nilai pkthdr->len yang merupakan sebuah data bentukan yang menyimpan panjang packet yang diolah
		if(isprint(packet[i])){ //fungsi kondisi yang mana jika karakter pada packet[i] dapat diprint / ada didalam karakter keyboard maka akan ditampilkan sesuai karakternya
			fprintf(file_csv,"%c",packet[i]); //fungsi yang menulis karakter packet[i] yang dapat di bica kedlaam file csv
		}else{
			fprintf(file_csv,".");  //jika dalam packet[i] tidak dapat dibaca / terdapat di keyboard maka digantikan dengan karakter titik dan dimasukkan kedalam file csv
		}
	}
	fprintf(file_csv,"\n"); //fungsi yang digunakan untuk menulis karakter enter agar operasi penulisan dalam file berpindah baris
}

void dump_ip_packet_pcap(struct iphdr *ip_proses){ //prosedur pemrosesan alamat ip address
	char src_ip[20], dest_ip[20];//array char untuk menyimpan source dan destination ip address
	strcpy(src_ip, inet_ntoa( *(struct in_addr *) &ip_proses->saddr) ); //melakukan string copy ke dalam src_ip yang sudah di alokasikan
																		//dengan mengcopy nilai dari proses pengubahan inet_ntoa
	strcpy(dest_ip, inet_ntoa( *(struct in_addr *) &ip_proses->daddr) );//melakukan string copy ke dalam dest_ip yang sudah di alokasikan
																		//dengan mengcopy nilai dari proses pengubahan inet_ntoa
	fprintf(file_csv,"%s, %s, %u, %ld,%d bytes,%d,%d,%d,%d,",src_ip,dest_ip,ip_proses->ttl,ntohs(ip_proses->tot_len)+sizeof(ip_proses)+10  ,((unsigned int)(ip_proses->ihl)*4),ntohs(ip_proses->tot_len),ntohs(ip_proses->id),ntohs(ip_proses->check),ntohs(ip_proses->frag_off)); //fungsi yang digunakan untuk memasukkan nilai yang telah tertampung didalam variabel kedalam file csv, yang mana ini merupakan hasil ekstraksi dari data header dengan data bentukan iphdr
}

void dump_tcp_packet_pcap(struct iphdr *ip_proses){ //prosedur pemrosesan dan pencetakan packet tcp
	char *u,*a,*p,*r,*s,*f; //deklarasi karakter berbentuk pointer agar dapat diubah setiap diperlukan
	char *ftp,*ssh,*telnet,*smtp,*whois,*http,*pop2,*pop3,*imap,*snmp,*https,*smb;//deklarasi karakter berbentuk pointer agar dapat diubah setiap diperlukan
	struct tcphdr *tcp_header; //deklarasi dari tipe data bentukan tcphdr yang digunakan untuk mengambil data dari packet yang menggunakan protokol tcp
	tcp_header = (struct tcphdr *) ( (char *) ip_proses + sizeof(struct iphdr) ); //kalkulasi tempat beradanya payload yang berisi data dari tcp
	//fungsi dibawah ini merupakan fungsi yang digunakan untuk mendapatkan flag yang terdapat di protokol tcp
	//flag start
	if(((unsigned int)tcp_header->urg) != 0){
		u ="U";
	}
	else{
		u="-";
	}
	if(((unsigned int)tcp_header->ack) != 0){
		a ="A";
	}
	else{
		a="-";
	}
	if(((unsigned int)tcp_header->psh) != 0){
		p ="P";
	}
	else{
		p="-";
	}
	if(((unsigned int)tcp_header->rst) != 0){
		r ="R";
	}
	else{
		r="-";
	}
	if(((unsigned int)tcp_header->syn) != 0){
		s="S";
	}
	else{
		s="-";
	}
	if(((unsigned int)tcp_header->fin) != 0){
		f ="F";
	}
	else{
		f="-";
	}
	//end flag
	//fungsi dibawah ini merupakan fungsi yang digunakan untuk menetukan layanan yang digunakan berdasarkan port yang digunakan
	//service
	if(ntohs(tcp_header->th_sport)==21 || ntohs(tcp_header->th_dport)==21){
		ftp = "ftp";
	}
	else{
		ftp ="-";
	}
	if(ntohs(tcp_header->th_sport)==22 || ntohs(tcp_header->th_dport)==22){
		ssh = "ssh";
	}
	else {
		ssh ="-";
	}
	if(ntohs(tcp_header->th_sport)==23 || ntohs(tcp_header->th_dport)==23){
		telnet = "telnet";
	}
	else{
		telnet = "-";
	}
	if(ntohs(tcp_header->th_sport)==25 || ntohs(tcp_header->th_dport)==25){
		smtp = "smtp";
	}
	else{
		smtp="-";
	}
	if(ntohs(tcp_header->th_sport)==43 || ntohs(tcp_header->th_dport)==43){
		whois = "whois";
	}
	else{
		whois ="-";
	}
	if(ntohs(tcp_header->th_sport)==80 || ntohs(tcp_header->th_dport)==80){
		http = "http";
	}
	else{
		http="-";
	}
	if(ntohs(tcp_header->th_sport)==109 || ntohs(tcp_header->th_dport)==109){
		pop2 = "pop2";
	}
	else{
		pop2 = "-";
	}
	if(ntohs(tcp_header->th_sport)==110 || ntohs(tcp_header->th_dport)==110){
		pop3 = "pop3";
	}
	else{
		pop3 ="-";
	}
	if(ntohs(tcp_header->th_sport)==139 || ntohs(tcp_header->th_dport)==139){
		smb= "smb";
	}
	else{
		smb="-";
	}
	if(ntohs(tcp_header->th_sport)==143 || ntohs(tcp_header->th_dport)==143){
		imap = "imap";
	}
	else{
		imap = "-";
	}
	if(ntohs(tcp_header->th_sport)==161 || ntohs(tcp_header->th_dport)==161){
		snmp = "snmp";
	}
	else{
		snmp = "-";
	}
	if(ntohs(tcp_header->th_sport)==443 || ntohs(tcp_header->th_dport)==443){
		https = "https";
	}
	else{
		https="-";
	}
	//end service
	//fprintf(file_csv,"%d,%d,%s%s%s%s%s%s,%u,%u,%u,%d,%d,%s%s%s%s%s%s%s%s%s%s%s%s,", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport),*&u,*&a,*&p,*&r,*&s,*&f,ntohl(tcp_header->th_ack),ntohl(tcp_header->th_seq),ntohs(tcp_header->th_win),ntohs(tcp_header->th_urp),ntohs(tcp_header->th_sum),*&ftp,*&ssh,*&telnet,*&smtp,*&whois,*&http,*&pop2,*&pop3,*&imap,*&snmp,*&https,*&smb); //fungsi yang digunakan untuk memasukkan nilai yang telah tertampung didalam variabel kedalam file csv, yang mana ini merupakan hasil ekstraksi dari data header dengan data bentukan tcphdr
	fprintf(file_csv,"%d,%d,%s%s%s%s%s%s,%u,%u,%u,%d,%s,%s,%s,%s,%d,%s%s%s%s%s%s%s%s%s%s%s%s,", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport),*&u,*&a,*&p,*&r,*&s,*&f,ntohl(tcp_header->th_ack),ntohl(tcp_header->th_seq),ntohs(tcp_header->th_win),ntohs(tcp_header->th_urp),kosong,kosong,kosong,kosong,ntohs(tcp_header->th_sum),*&ftp,*&ssh,*&telnet,*&smtp,*&whois,*&http,*&pop2,*&pop3,*&imap,*&snmp,*&https,*&smb); //fungsi yang digunakan untuk memasukkan nilai yang telah tertampung didalam variabel kedalam file csv, yang mana ini merupakan hasil ekstraksi dari data header dengan data bentukan tcphdr
}

void dump_udp_packet_pcap(struct iphdr *ip_proses){ //proseduer pemrosesan dan pencetakan packet udp
	char *ftp,*ssh,*telnet,*smtp,*whois,*http,*pop2,*pop3,*imap,*snmp,*https,*dns;//deklarasi karakter berbentuk pointer agar dapat diubah setiap diperlukan
	struct udphdr *udp_header; //deklarasi dari tipe data bentukan udphdr yang digunakan untuk mengambil data dari packet yang menggunakan protokol udp
	udp_header = (struct udphdr *) ( (char *) ip_proses + sizeof(struct iphdr) );//kalkulasi tempat beradanya payload yang berisi data dari udp
	//fungsi dibawah ini merupakan fungsi yang digunakan untuk menetukan layanan yang digunakan berdasarkan port yang digunakan
	//service
	if(ntohs(udp_header->uh_sport)==21 || ntohs(udp_header->uh_dport)==21){
		ftp = "ftp";
	}
	else{
		ftp ="-";
	}
	if(ntohs(udp_header->uh_sport)==22 || ntohs(udp_header->uh_dport)==22){
		ssh = "ssh";
	}
	else {
		ssh ="-";
	}
	if(ntohs(udp_header->uh_sport)==23 || ntohs(udp_header->uh_dport)==23){
		telnet = "telnet";
	}
	else{
		telnet = "-";
	}
	if(ntohs(udp_header->uh_sport)==25 || ntohs(udp_header->uh_dport)==25){
		smtp = "smtp";
	}
	else{
		smtp="-";
	}
	if(ntohs(udp_header->uh_sport)==43 || ntohs(udp_header->uh_dport)==43){
		whois = "whois";
	}
	else{
		whois ="-";
	}
	if(ntohs(udp_header->uh_sport)==53 || ntohs(udp_header->uh_dport)==53){
		dns = "dns";
	}
	else{
		dns ="-";
	}
	if(ntohs(udp_header->uh_sport)==80 || ntohs(udp_header->uh_dport)==80){
		http = "http";
	}
	else{
		http="";
	}
	if(ntohs(udp_header->uh_sport)==109 || ntohs(udp_header->uh_dport)==109){
		pop2 = "pop2";
	}
	else{
		pop2 = "-";
	}
	if(ntohs(udp_header->uh_sport)==110 || ntohs(udp_header->uh_dport)==110){
		pop3 = "pop3";
	}
	else{
		pop3 ="-";
	}
	if(ntohs(udp_header->uh_sport)==143 || ntohs(udp_header->uh_dport)==143){
		imap = "imap";
	}
	else{
		imap = "-";
	}
	if(ntohs(udp_header->uh_sport)==161 || ntohs(udp_header->uh_dport)==161){
		snmp = "snmp";
	}
	else{
		snmp = "-";
	}
	if(ntohs(udp_header->uh_sport)==443 || ntohs(udp_header->uh_dport)==443){
		https = "https";
	}
	else{
		https="-";
	}
	//end service
	//fprintf(file_csv,"%d,%d,%s,%s,%s,%s,%s,%d,%s%s%s%s%s%s%s%s%s%s%s%s,",ntohs(udp_header->uh_sport),ntohs(udp_header->uh_dport),kosong,kosong,kosong,kosong,kosong,ntohs(udp_header->uh_sum),*&ftp,*&ssh,*&telnet,*&smtp,*&whois,*&http,*&pop2,*&pop3,*&imap,*&snmp,*&https,*&dns); //fungsi yang digunakan untuk memasukkan nilai yang telah tertampung didalam variabel kedalam file csv, yang mana ini merupakan hasil ekstraksi dari data header dengan data bentukan udphdr
	fprintf(file_csv,"%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%d,%s%s%s%s%s%s%s%s%s%s%s%s,",ntohs(udp_header->uh_sport),ntohs(udp_header->uh_dport),kosong,kosong,kosong,kosong,kosong,kosong,kosong,kosong,kosong,ntohs(udp_header->uh_sum),*&ftp,*&ssh,*&telnet,*&smtp,*&whois,*&http,*&pop2,*&pop3,*&imap,*&snmp,*&https,*&dns); //fungsi yang digunakan untuk memasukkan nilai yang telah tertampung didalam variabel kedalam file csv, yang mana ini merupakan hasil ekstraksi dari data header dengan data bentukan udphdr
}

void dump_icmp_packet_pcap(struct iphdr *ip_proses){ //proseduer pemrosesan dan pencetakan icmp packet
	//char *ftp,*ssh,*telnet,*smtp,*whois,*http,*pop2,*pop3,*imap,*snmp,*https,*dns;//deklarasi karakter berbentuk pointer agar dapat diubah setiap diperlukan
	//struct udphdr *udp_header;//deklarasi dari tipe data bentukan udphdr yang digunakan untuk mengambil data dari packet yang menggunakan protokol udp
	struct icmphdr *icmp_hdr;//deklarasi dari tipe data bentukan icmphdr yang digunakan untuk mengambil data dari packet yang menggunakan protokol icmp
	icmp_hdr = (struct icmphdr *) ( (char *) ip_proses + sizeof(struct iphdr));//kalkulasi tempat beradanya payload yang berisi data dari icmp
	//udp_header = (struct udphdr *) ( (char *) ip_proses + sizeof(struct iphdr)+sizeof(struct icmphdr)+sizeof(struct iphdr));//kalkulasi tempat beradanya payload yang berisi data dari udp
	//filter code adn type icmp
		fprintf(file_csv,"%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%d,%d,%s,\n",kosong,kosong,kosong,kosong,kosong,kosong,kosong,icmp_hdr->code,icmp_hdr->type,ntohs(icmp_hdr->un.echo.id),ntohs(icmp_hdr->un.echo.sequence),ntohs(icmp_hdr->checksum),kosong);

	}

void proses_packet_pcap(u_char *args, const struct pcap_pkthdr *header_pcap,const u_char *file_pcap){ //prosedur pemrosesan packet, prosedur ini akan memanggil prosedur tcp, udp dan icmp untuk pemrosesan lebih lanjut
	struct ether_header *ethr_header; //pendeklarasian tipe data bentukan ether_header kedalam varibel pointer ethr_header
	struct iphdr *ip_header; //pendeklarasin tipe data bentukan iphdr kedalam variabel pointer ip_header
	fprintf(file_csv,"%d,",jumlah_packet); //fungsi yang digunkan untuk menulis jumlah packet kedalam file csv
	ethr_header = (struct ether_header *)file_pcap;
	//printf("%d\n",sizeof(ethr_header)); //kalkulasi tempat payload ethr_header berada
	ip_header = (struct iphdr *) (file_pcap + sizeof(struct ether_header)); //kalkulasi tempat payload ip_header berada
	//ip_header = (struct iphdr *); //(file_pcap + sizeof(struct ether_header)); //kalkulasi tempat payload ip_header berada
	//printf("%d\n",sizeof(ip_header));
	if(ntohs(ethr_header->ether_type) == ETHERTYPE_ARP){
		fprintf(file_csv,"ARP\n");//fungsi yang digunakan untuk menulis hasil ARP dalam file csv jika protokol ARP
	}
	else if(ip_header->protocol == IPPROTO_ICMP){
		fprintf(file_csv,"ICMP,");//fungsi yang digunakan untuk menulis hasil ICMP dalam file csv jika protokol ICMP
		timestamp_to_readable(header_pcap->ts);
		dump_ip_packet_pcap(ip_header);//prosedur yang digunakan untuk mengolah data ip
		dump_icmp_packet_pcap(ip_header);//prosedur yang digunakan untuk mengolah data icmp
		//fprintf(file_csv,"\n");
		//print_payload(header_pcap,file_pcap);//prosedur yang digunakan untuk mengolah data payload
	}
	else if(ip_header->protocol == IPPROTO_TCP){
		fprintf(file_csv,"TCP,");//fungsi yang digunakan untuk menulis hasil TCP dalam file csv jika protokol TCP
		timestamp_to_readable(header_pcap->ts);
		dump_ip_packet_pcap(ip_header);//prosedur yang digunakan untuk mengolah data ip
		dump_tcp_packet_pcap(ip_header);//prosedur yang digunakan untuk mengolah data tcp
		print_payload(header_pcap,file_pcap);//prosedur yang digunakan untuk mengolah data payload
	}
	else if(ip_header->protocol == IPPROTO_UDP) {
		fprintf(file_csv,"UDP,"); //fungsi yang digunakan untuk menulis hasil UDP dalam file csv jika protokol UDP
		timestamp_to_readable(header_pcap->ts);
		dump_ip_packet_pcap(ip_header);//prosedur yang digunakan untuk mengolah data ip
		dump_udp_packet_pcap(ip_header);//prosedur yang digunakan untuk mengolah data udp
		print_payload(header_pcap,file_pcap);//prosedur yang digunakan untuk mengolah data payload
	}
	else {
		fprintf(file_csv,"Other\n");//fungsi yang digunakan untuk menulis hasil other dalam file csv jika protokol tidak diketahui
	}
jumlah_packet++;//varibael penampung untuk menghitung jumlah paket yang telah di proses
}

int main(int argc, char **argv){
	char argumen; //varbel penyimpan inputa dari unistd (optarg)
	char *file_in=""; //varibel penyimpan path
	char *file_out=""; //variabel penyimpan nama output file
	char errbuff[PCAP_ERRBUF_SIZE]; //variabel buffer penyimpanan file pcap
	pcap_t *file_pcap; //variabel penyimpan file pcap
	if(argc<=3){ //jika tidak ada argumen yang dimasukkan maka ini akan bernilai benar
		fprintf(stderr,RED "Missing argument!!!!!\n" RESET
		YEL "Penggunaan program  %s -f <lokasi/nama file>.pcap -o <dump file>.csv\n " RESET,argv[0]); //pesan yang akan ditampilkan berwarna merah yang mana user kurang dalam memberikan input argumen yang dibutuhkan
		return 1; //seperti exit(1) ini merupakan fungsi yang memaksa program untuk berhenti dikarenakan kurangnya argumen yang dimasukkan oelah user
	}
	while((argumen=getopt(argc,argv,"f:o:"))!=EOF){  //pemilihan argumen masukan dari optarg
		switch(argumen){ //memilih argumen yang sesuai
			case 'f':
			file_in = optarg;//nilai dari optarg yang didapat dari input perintah dan memasukkannyha dalam variabel filenya dengan tipe data string/char
			break;
			case 'o':
			file_out = optarg;//nilai dari optarg yang didapat dari input perintah dan memasukkannyha dalam variabel filenya dengan tipe data string/char
			break;
			default :
			fprintf(stdout,RED "Argumen tidak tersedia\n" RESET);//jika agumen yang dimasukkan tidak ada dalam pilihan maka tampilkan
			break;
		}
	}
	file_pcap = pcap_open_offline(file_in,errbuff); //membuka file pcap dan dimasukkan dalam file_pcap yang merupakan variabel penyimpannya
	if(file_pcap == NULL){ //jika file_pcap tidak terload maka if ini bernilai benar
		printf(RED "File tidak berhasil dibuka, periksa nama file anda\n" RESET);//pesan kegagalan jika file gagal dibuka
		pcap_close(file_pcap); //close file pcap dalam variabel
		exit(1); //fungsi yang memaksa pemberhentian program dikarenakan kegagalan dalam pembacaan file pcap
	}
	else {
		printf(GRN "File %s berhasil dibuka\n" RESET,file_in); //pesan yang menyatakan bahwa file pcap berhasil dibuka
	}
	file_csv = fopen(file_out,"w"); //fungsi yang digunakan untuk membuat sebuah file csv dengan nama yang telah ditentukan oleha user sebelum program berjalan
	if(file_csv == NULL){ //jika file csv gagal dibuat maka if ini bernilai benar
		printf(RED "Gagal membuat file %s\n" RESET,file_out); //pesan kegagalan berwarna merah yang menyatakan kegagalan dalam pembuatan file csv sebagai file output
		pcap_close(file_pcap); //close file pcap dalam variabel
		fclose(file_csv); //close file csv dalam variabel
		exit(1); //fungsi yang akan memaksa program untuk berhenti dikarenakan kegagalan dalam pembuatan file output csv
	}
	else{
		printf(GRN "Berhasil membuat file %s\n" RESET,file_out);//pesan berwarna hijau yang menyatakan bahwa file output berhasil dibuat
	}
	//fprintf(file_csv,"No.Packet, Protocol,Time, Epoch_Time ,IP_Source, IP_Dest, TTL, Panjang_Data_Capture,Lenght_Header_IP, Total_Lenght_IP, Identification_Header_IP, Checksum_Header_IP,Fragment_Offset_IP, P_Source, P_Dest, Flags, Ack, Seq, Window, Urg_Pointer,Checksum_Protokol, Service, Payload\n"); //merupakan perintah yang digunakan untuk menulis kata dalam petik didalam file .csv yang tadi sudah dibuat, karena file csv merupakan file yang dipisahkan oleh koma untuk membtnuk sebuah pemisah, maka diberilah koma pada setiap kata setelah pencetakan sehingga output akan terlihat rapi
	fprintf(file_csv,"No.Packet, Protocol,Time, Epoch_Time ,IP_Source, IP_Dest, TTL, Lenght_Header_IP, Total_Lenght_IP, Identification_Header_IP, Checksum_Header_IP,Fragment_Offset_IP, P_Source, P_Dest, Flags, Ack, Seq, Window, Urg_Pointer, Code_ICMP,Type ICMP,ID ICMP,Seq ICMP,Checksum_Protokol, Service, Payload\n"); //merupakan perintah yang digunakan untuk menulis kata dalam petik didalam file .csv yang tadi sudah dibuat, karena file csv merupakan file yang dipisahkan oleh koma untuk membtnuk sebuah pemisah, maka diberilah koma pada setiap kata setelah pencetakan sehingga output akan terlihat rapi
	jumlah_packet=1; //penghitung packet yang di di baca di fila pcap dan yang di proses
	printf(YEL "Report Error ke email:09121001042@students.ilkom.unsri.ac.id\n" RESET); //pesan berwarna kuning untuk mengirimkan error ke alamat email yang tercantum
	printf(GRN "Processing packet....\n"   RESET); //pesan berwarna hijau yang menyatakan pemrosesan packet sedang berlangsung
	pcap_loop(file_pcap, -1,proses_packet_pcap, NULL); //fungsi loop yang terus berjalan hingga seluruh baris dalam file pcap sudah di olah
	pcap_close(file_pcap); //close file pcap dalam variabel, menutup file pcap yang sudah dibuka
	fclose(file_csv); //meutup file csv setelah operasi selesai dilakukan
	printf(GRN "Selesai....\n"   RESET); //pesan berwarna hijau saat packet selesai di proses
	return 0;
}
