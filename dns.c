#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>

#define DNS_SERVER "8.8.8.8"

/* Vastaanotetun viestin maksimikoko. */
#define BUFFER_SIZE 1000
/* Lähetettävän kyselyn maksimikoko. */
#define QUERY_SIZE 1000

struct Header 
{
    unsigned short id;
    unsigned short parameter;
    unsigned short n_questions;
    unsigned short n_answers;
    unsigned short n_authorities;
    unsigned short n_additional;
};

/* Question - domain name */
struct Question
{
    unsigned short queryType;
    unsigned short queryClass;
};

/* Resource - data */
struct Resource
{
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short dataLength;
};

char *parseQuery(unsigned char *msg, size_t addrLen)
{
    /* Osoitin hdr määrittää otsakkeen kenttien paikat vastauksessa. */
    struct Header *hdr = (struct Header *)msg;
    int n_answers = ntohs(hdr->n_answers); //vastausten määrä, ntohs =
					   //bittijärjestys kotikoneen mukaiseksi
    

    /* Mennään eteenpäin vastauksessa. */
    msg = msg + sizeof(struct Header) + addrLen + sizeof(struct Question) + 3;

    struct Resource *res = (struct Resource *)msg;

    /* Käydään lävitse vastauksia. */
    char *ip = NULL; int i;
    for (i=0; i<n_answers; i++) {
	
	/* Etsitään ipv4-osoite. */
	if (ntohs(res->type) == 1) {
	    ip = calloc(res->dataLength, 1);
	    memcpy(ip, inet_ntoa(*(struct in_addr *)(msg + sizeof(struct
	    Resource) - 2)), 16);
	    break;
	}

	/* Jos kyseinen vastaus ei ole ipv4-osoite, mennään seuraavaan
	   vastaukseen. */
	msg = msg + ntohs(res->dataLength) + sizeof(struct Resource);
	res = (struct Resource *)msg;
	
    }
    
    if (!ip) {
	printf("Verkkotunnukselle ei löytynyt ip-osoitetta.\n");
	exit(-1);
    }
    
    return ip;
}


unsigned char *convertDnsName(char *dname) 
{
    unsigned char *dnsName = calloc(strlen(dname)+10,1);

    /* Osoitin ptr osoittaa uuden merkkijonon loppuun. */
    unsigned char *ptr = dnsName;
    int len = 0; //osajonojen pituus pisteiden välissä

    /* Komento strtok muokkaa alkuperäistä merkkijonoa, joten luodaan uusi. */
    char *tmpName = calloc(strlen(dname)+10,1);
    strcpy(tmpName, dname);

    char *token = strtok(tmpName, ".");
    
    while (token != NULL) {
	len = (unsigned char)strlen(token);

	/* (i) '3' (ii) '3www6' (iii) '3www6google3' */
	*ptr++ = len;
	
	/* (i) '3www' (ii) '3www6google' (iii) 3www6google3com */
	memcpy(ptr, token, len);
	ptr += len;
	
	token = strtok(NULL, ".");
    }

    /* '3www6google3com0' */
    *ptr++ = 0;
    *ptr = 0;
    
    dnsName[strlen(dname)+1] = '\0';

    free(tmpName);
    return dnsName;
}

unsigned char *getMessage(int s)
{
    unsigned char *msg = calloc(BUFFER_SIZE, 1);
    if (recvfrom(s, msg, BUFFER_SIZE, 0, NULL, NULL) < 0) {
	printf("Virhe viestin vastaanottamisessa: %d\n", errno);
	exit(-1);
    }
    
    return msg;
}

void sendMessage(int s, unsigned char *msg, size_t addrLen, struct sockaddr_in *addr)
{
    /* Viestin pituus on määritettävä "käsin". */
    size_t queryLen = sizeof(struct Header) + sizeof(struct Question) + addrLen;
    
    if (sendto(s, msg, queryLen+2, 0, (struct sockaddr *)addr, sizeof(*addr)) < 0)
    {
	printf("Virhe viestin lähettämisessä: %d\n", errno);
	exit(-1);		
    }
}

unsigned char *createQuery(char *dname) 
{
    /* Lähetettävä kysely on query-muuttujassa. */
    unsigned char *query = calloc(QUERY_SIZE, 1);

    /* Osoitin hdr määrittää otsakkeen kenttien paikat kyselyssä. */
    struct Header *hdr = (struct Header *)query;
    
    hdr->id = htons(rand()); //satunnainen id

    /* bitti 7+8: halutaan rekursiivinen toteutus. */
    hdr->parameter = htons(0x0180); //0000 0001 1000 0000
    hdr->n_questions = htons(1); //yksi osoite selvitettävänä, htons = verkkobittijärjestys
    hdr->n_answers = 0;
    hdr->n_authorities = 0;
    hdr->n_additional = 0;

    /* Muutetaan verkkotunnus dns-kyselyn vaatimaan muotoon,
       esim. www.google.com -> 3www6google3com0. */
    unsigned char *dnsName = convertDnsName(dname);
    size_t dnsNameLen = strlen((char*)dnsName);

    /* Tallennetaan muokattu verkkotunnus oikeaan paikkaan kyselyssä. */
    memcpy(query+sizeof(struct Header), dnsName, dnsNameLen);

    /* Osoitin qst määrittää kysymyksen kenttien paikat kyselyssä (- dnsname). */
    struct Question *qst = (struct Question *)(query+sizeof(struct Header)+dnsNameLen+1);
   
    qst->queryType = htons(1);
    qst->queryClass = htons(1);
    
    free(dnsName);
    return query;
}	

struct sockaddr_in *getSendAddress(void)
{
    /* Tehdään struktuuri, jossa on dns-palvelimen ipv4-osoite (DNS_SERVER) ja
     * portti (53). */
    struct sockaddr_in *dnsAddr = calloc(sizeof(struct sockaddr_in), 1);
    
    dnsAddr->sin_family = AF_INET;
    dnsAddr->sin_port = htons(53);
    dnsAddr->sin_addr.s_addr = inet_addr(DNS_SERVER);

    return dnsAddr;
}

int getSocket(void) 
{
    /* Luodaan ipv4-soketti. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
	exit(-1);

    return s;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
	printf("Käyttö: ./dns <verkkotunnus>\n");
	return -1;
    }
    char *dname = argv[1];

    /* Luodaan uusi udp-soketti. */
    int s = getSocket();

    /* Määritetään dns-palvelin, johon kysely lähetetään. */
    struct sockaddr_in *dnsAddr = getSendAddress();

    /* Tehdään uusi kysely. */
    unsigned char *sendMsg = createQuery(dname);

    /* Lähetetään kysely palvelimelle. */
    sendMessage(s, sendMsg, strlen(dname)+1, dnsAddr);
    free(dnsAddr);
    free(sendMsg);

    /* Vastaanotetaan kyselyn tulos. */
    unsigned char *recvMsg = getMessage(s);

    /* Selvitetään ipv4-osoite. */
    char *ip = parseQuery(recvMsg, strlen(dname)+1);
    free(recvMsg);
    
    printf("%s\n", ip);
    free(ip);
    
    return 0;
}

