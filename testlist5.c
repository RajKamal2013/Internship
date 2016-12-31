/*standard libraries section... for details visit www.cplusplus.com */
#include<stdio.h>             //library for standard input and output 
#include<stdlib.h>            //library for exit() function
#include<string.h>            //library for string opertions and memset()
#include<errno.h>             //library for handling the error
/*standard library for thread and packet capture */
#include<pthread.h>          //library for thread management 
#include<pcap.h>             //library for paket capture 

/*standard libraries for creating timer */
#include<time.h>             //C library for time related function
#include<sys/time.h>         //linux libraries for time
#include<signal.h>           //C library for signal management
#include<unistd.h>           //linux libraries for the system programming functions
#include<sys/types.h>

#include<sys/socket.h>       //libraries for socket related functions
#include<arpa/inet.h>        //library for networking functions inet_ntoa()
#include<net/ethernet.h>     //alternate library for the ethernet header
#include<netinet/in.h>       //library for ip address and structure conversion
#include<netinet/if_ether.h> //library for ethernet header declaration and function 
#include<netinet/ip.h>       //library for ip header declaration and functions
#include<netinet/ip_icmp.h>  //library for icmp haeder declaration and function
#include<netinet/udp.h>      //library for udp header declaration and function
#include<netinet/tcp.h>      //library for tcp header declaration and function

#define ARP_REQUEST 1        //ARP Request
#define ARP_REPLY 2          //ARP Reply
#define expireTime 3      //setting expiry time or moving window
#define intervalTime 3     //setting restarting time for the timer       
//************************STRUCTURE DEFINATIONS*****************************//

/*structure declaration for the ARP Header */
struct arp_header
 {
   u_int16_t htype;          /*hardware Type */
   u_int16_t ptype;          /*protocol Type*/
   u_char hlen;              /*Hardware Address Length */
   u_char plen;              /*Protocol Address Length */
   u_int16_t oper;           /*operation code  */
   u_char sha[6];            /*sender hardware address */
   u_char spa[4];            /*sender IP address */
   u_char dha[6];            /*Target Hardware Address */
   u_char dpa[4];            /*Target IP address */
};

/*structure declaration for tcp header */
struct tcp_header
{
   u_short th_sport;       /*source port*/
   u_short th_dport;       /*destination port */
   u_int th_seq;           /*sequence number*/
   u_int th_ack;           /*acknowledge number*/
   u_char th_offx2;        /*data offset,rsvd*/
   #define TH_OFF(th)    (((th)->th_offx2 & oxf0) >> 4)
   u_char th_flags;
   #define TH_FIN  0x01
   #define TH_SYN  0x02
   #define TH_RST  0x04
   #define TH_PUSH 0x08
   #define TH_ACK  0x10
   #define TH_URG  0x20
   #define TH_ECE  0x40
   #define TH_CWR  0x80
   #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
   u_short th_win;         /*window*/
   u_short th_sum;         /*checksum*/
   u_short th_urp;         /*urgent pointer*/
};

/*structure declaration for the packet size */
struct pktsz_node     
{
  int size;                  /*packet size in bytes */
  int count;                 /*count of the packet */
  struct pktsz_node  *next;  
};

/*structure for maintaining  the source ip list */
struct ips_node     
{
  char ip[200];              /*ip address */
  int count;                 /*count of the ip */
  struct ips_node  *next;
};

/*structure for  maintaining the destination ip list */
struct ipd_node
{
  char ip[200];               /*ip address */
  int count;                  /*count of the ip */
  struct ipd_node *next;
};

/*structure for maintaining the source port*/
struct sport_node
{
  char ip[200];           /*source ip address*/
  int port;               /*port number*/
  int count;              /*count */
  struct sport_node *next;
};

/*structure for maintaining the destination port*/
struct dport_node
{
  char ip[200];           /*destination ip address*/
  int port;               /*port number */
  int count;              /*count*/
  struct dport_node *next;
};

//******************GLOBAL VARIABLES DECLARATIONS*****************************//


/*declaring Global variables */
pthread_t ips_thread[300000],ipd_thread[300000],arp_thread[300000],size_thread[300000],sport_thread[300000],dport_thread[300000]; /*array of threads for packet characteristics ip-source,ip des                                                                                         -tination,size of the packet ,arp packets*/
int ips_packet_count=0;        /*count total number of the ip_source packet*/  
int ips_node_count=0;          /*count number of the distinct ip_source packet*/
int ipd_packet_count=0;        /*count total number of the ip_destination packet*/      
int ipd_node_count=0;          /*count number of the distinct ip_destination packet*/
int packet_size_count=0;       /*count total number of differnt length of packet */
int packet_size_node_count=0;  /*count distinct number of different length of packets*/
int sport_packet_count =0;     /*count total number of differnt source port*/
int sport_node_count=0;         /*count distinct number of distinct port*/
int dport_packet_count=0;      /*count total number of differnt destination port                                */
int dport_node_count=0;        /*count total number of distinct port*/
int ether_packet_count=0;      /*count total number of the ethernet packet*/
int ether_node_count=0;        /*count  number of the distinct  ethernet packet*/
int arp_packet_count=0;        /*count  total number of the arp packet*/
int arp_node_count=0;          /*count  number of the distinct arp packet*/
int ips_thread_count =0;       /*keep record  of the source ip threads*/
int ipd_thread_count =0;       /*keep record  of the destination ip threads*/
int size_thread_count=0;       /*keep record  of the packet size threads*/
int arp_thread_count =0;       /*keep record  of the arp packet threads*/
int sport_thread_count=0;      /*keep record  of the sport packet threads*/
int dport_thread_count=0;      /*keep record  of the destination port threads*/
char date[200];                /*keep record  of the time instant*/ 
/*declaring array of timers for the packet attributes ,size,source ip,destination ip,source port and destination port*/
timer_t size_timer[300000],ips_timer[300000],ipd_timer[300000],sport_timer[300000],dport_timer[300000];
timer_t print_timer[300000];   /*timer for printing the results at the time out and calculate entropy*/
int size_timer_count=0;
int print_timer_count=0;
int ips_timer_count =0;
int ipd_timer_count=0;
int sport_timer_count=0;
int dport_timer_count=0;
/*Global declaration for the structure */
struct pktsz_node *front_pktsz=NULL;
struct ips_node *front_ips=NULL;
struct ipd_node *front_ipd=NULL;
struct sport_node *front_sport=NULL;
struct dport_node *front_dport=NULL;



//************************FUCNTIONS DECLARATIONS******************************//

/*declaring functions */
/*functions for packet opertions*/
/*void process_packet(u_char *,const struct pcap_pkthdr *,const u_char *);       
void process_ip_packet(const u_char *,int);
void print_ip_packet(const u_char *,int);
void print_tcp_packet(const u_char *,int);
void print_udp_packet(const u_char *,int);
void print_udp_packet(const u_char *,int);
void print_icmp_pcaket(const u_char *,int);
void print_data(const u_char *,int);*/

/*function prototypes for opearating paket size list */
struct pktsz_node *search_pktsz(struct pktsz_node *,int);
void insert_pktsz(struct pktsz_node **,int);
void display_pktsz(struct pktsz_node *);
int remove_pktsz(struct pktsz_node **);
/*function prototypes for operating source ip list */
struct ips_node *search_ips(struct ips_node *,char *);
void insert_ips(struct ips_node **,char *);
void display_ips(struct ips_node *);
int remove_ips(struct ips_node **);
/*function prototypes for operating destination ip list */
struct ipd_node *search_ipd(struct ipd_node *,char *);
void insert_ipd(struct ipd_node **,char *);
void display_ipd(struct ipd_node *);
int remove_ipd(struct ipd_node **);
/*function prototypes for maintaining souce port list*/
struct sport_node *search_sport(struct sport_node *,char *,int);
void insert_sport(struct sport_node **,char *,int);
void display_sport(struct sport_node *);
int remove_sport(struct sport_node **);
/*function prototypes for maintaining destination port list*/
struct dport_node *search_dport(struct dport_node *,char *,int);
void insert_dport(struct dport_node **,char *,int);
void display_dport(struct dport_node *);
int remove_dport(struct dport_node **);
/*function for maintaining moving window using timers*/
int find_timer(timer_t *);
static void timerHandler(int ,siginfo_t *,void *);
static int makeTimer(char *,timer_t *,int,int);
/*function for handling threads*/
void *size_function(void *);
void *ips_function(void *);
void *ipd_function(void *);
void *sport_function(void *);
void *dport_function(void *);
/*function for displaying number of ARP packet*/
//void display_arp(void);


//**************************DEFINING FUNCTIONS *******************************//

//**************************TIMER FUNCTIONS**********************************//
/*find which type of timer */
int find_timer(timer_t *tidp)
{
   int ret=0;
   int i;
   int ret1;
   for(i=0;i<300000;i++)
   {
      if(*tidp==size_timer[i])               /*timer is for packet size*/
         ret=1;
      if(*tidp==print_timer[i])              /*timer for calculating and printin                                               -g the results */
        ret=2; 
      if(*tidp==ips_timer[i])                /*timer for  source ip */
        ret =3;
      if(*tidp==ipd_timer[i])                /*timer for destination ip */
          ret =4;
      if(*tidp==sport_timer[i])       /*timer for the source port */
          ret =5;
      if(*tidp==dport_timer[i])        /*timer for the destination port */
           ret =6;
   }
   return ret;
}       
    

/*timer handler functin for the timer */
//siginfo_t is a kind of structure that which keeps complete information about signals.For more details check /include/sys/time.h
static void timerHandler(int sig,siginfo_t *si,void *uc)
 {
    int i,j;
    int type,ret;
    timer_t *tidp;
    tidp=si->si_value.sival_ptr;     /*signal identification*/
    type=find_timer(tidp);           /*find which kind of timer has time out*/
    if(type==1)                      /*packet size timer time out */
      {
            remove_pktsz(&front_pktsz);    
            ret=timer_delete(*tidp);
            if(ret==-1)
             perror("timer_delete(...)");
      
      }
    if(type==2)                       /*print timer has time out */
      {
            printf("******************************PACKET INFORMATION AT TIME %s",date);
            display_pktsz(front_pktsz);
            display_ips(front_ips);
            display_ipd(front_ipd);
            display_sport(front_sport);
            display_dport(front_dport);
            printf("ARP_PACKET_COUNT:%d\n",arp_packet_count);
            printf("\n");
      }
    if(type==3)                      /*ips timer has time out */
      {
            remove_ips(&front_ips);
            ret=timer_delete(*tidp);
            if(ret==-1)
               perror("timer_delete(...)");
     }
    if(type==4)
      {
            remove_ipd(&front_ipd);    /*ipd timer has time out */
            ret=timer_delete(*tidp);
            if(ret==-1)
                 perror("timer_delete(...)");
     }
    if(type==5)                       /*sport timer has time out*/
      {
              remove_sport(&front_sport);
              ret=timer_delete(*tidp);
              if(ret==-1)
                  perror("timer_delete(...)");
      }
    if(type==6)                        /*dport timer has time out*/
      {
              remove_dport(&front_dport);
              ret=timer_delete(*tidp);
              if(ret==-1)
                    perror("timer_delete(...)");
      } 
    
     if(type==0)                        /*unknown */
          printf("Error Invalid type \n");
     
     
 }


/*Below function uses time.h,sys/time.h,signal.h libraries and inbuilt functions timer_create(...),timer_settime(...).check includes files to get complete info
 struct sigevent ,sigaction are defined in signal.h and give information about signals.struct itimerspec used to set timer and again to reset it.*/
//            struct sigaction {
//                 void (*sa_handler)(int);   /* signal handler or function */
//                 void (*sa_sigaction)(int, siginfo_t *, void *);/*advance hand                                     ler used only when sa_falg is SA_SIGINFO
//                 sigset_t sa_mask;         /* signals to block */
//                 int sa_flags;             /* flags */
//                 void (*sa_restorer)(void); /* obsolete and non-POSIX */
//                  };
//int sigaction (int signo,const struct sigaction *act,struct sigaction *oldact);:-A call to sigaction( ) changes the behavior of the signal identified by signo, whichcan be any value except those associated with SIGKILL and SIGSTOP. If act is not NULL,the system call changes the current behavior of the signal as specified by act.


/*function that initialises timer */
static int makeTimer(char *name,timer_t *timerID,int expireMS,int intervalMS)
{
  int ret;                          /*varaible to handle error*/
  struct sigevent te;               /*structure for keeping information about                                         signals*/
  struct itimerspec its;            /*structure for handling time of timer */
  struct sigaction sa;              /*structure for handling signals*/
  int sigNo=SIGRTMIN;               /*user genearated signals*/
  
/*set up the signal handler */
  sa.sa_flags=SA_SIGINFO;           /*flag that causes sa_sigaction to use as si                                     -gnal handler function*/
  sa.sa_sigaction=timerHandler;     /*a function that define what to do when tim                                      -er expires*/
  sigemptyset(&sa.sa_mask);         /*function that make signal set NULL,no sign                                     -al to block*/
  ret=sigaction(sigNo,&sa,NULL);    /*function that actually behind timerHadler                                      causing structure sigaction to get active*/
  if(ret==-1)                      
   {
     fprintf(stderr, " sigaction(...):Failed to setup signal handler for %s",name);
     return(-1);
   }
  /*SIGEV_SIGNAL :On timer expiration, the kernel sends the process the signal specified bysigev_signo. In the signal handler, si_value is set to sigev_value.*/
 
   te.sigev_notify=SIGEV_SIGNAL;     /*signal generated on timer expiration*/
   te.sigev_signo=sigNo;             /*signal number */
   te.sigev_value.sival_ptr=timerID; /*registering timer with the signal*/ 
   timer_create(CLOCK_REALTIME,&te,timerID); /*library function that creates tim                                              er  with timerID*/
   
   its.it_interval.tv_sec=intervalMS; /*time in seconds to restart the timer */
   its.it_interval.tv_nsec=0;         /*time in nanoseconds to reset*/
   its.it_value.tv_sec=expireMS;      /*time in seconds to set timer expire*/
   its.it_value.tv_nsec=0;            /*time in nanoseconds to set timer*/
   timer_settime(*timerID,0,&its,NULL); /*library function to set the timer*/
   return 0;
} 


//***********************THREAD FUNCTIONS***********************************//
/*thread handler function for packet size*/
void *size_function(void *ptr)
{
   int ret;
   char str1[]="size Timer";
   makeTimer(str1,&size_timer[size_timer_count++],expireTime,0);
   /*reset the timer_count ,circular link is better option but due to time const     aint I am doing this ,sorry */
    if(size_timer_count==300000)
        size_timer_count=0;
}

/*thread function for source ip */
void *ips_function(void *ptr)
 {
    char str1[]="source IP Timer";
    makeTimer(str1,&ips_timer[ips_timer_count++],expireTime,0);
    /*reset the timer_count ,circular link is better option but due to time cons      taint I am doing this ,sorry */
    if(ips_timer_count==300000)
         ips_timer_count=0;
 }

/*thread function for destination ip*/
void *ipd_function(void *ptr)
{
    char str1[]="Destination IP Timer";
    makeTimer(str1,&ipd_timer[ipd_timer_count++],expireTime,0);
    /*reset the timer_count ,circular link is better option but due to time cons     -taint I am doing this ,sorry */
    if(ipd_timer_count==300000)
        ipd_timer_count=0;
}

/*thread function for source  port*/
void *sport_function(void *ptr)
{
   char str1[]="Source port Timer";
   makeTimer(str1,&sport_timer[sport_timer_count++],expireTime,0);  
    /*reset the timer_count ,circular link is better option but due to time cons     -taint I am doing this ,sorry */
   if(sport_timer_count==300000)
        sport_timer_count=0;
}

/*thread function for destination port*/
void *dport_function(void *ptr)
 {
    char str1[]="Destination port Timer";
    makeTimer(str1,&dport_timer[dport_timer_count++],expireTime,0);
   /*reset the timer_count ,circular link is better option but due to time cons     -taint I am doing this ,sorry */
    if(dport_timer_count==300000)
         dport_timer_count=0;
 }

//**************************LINKED LIST FUNCTIONS****************************//

/*I have single Linked list with standard processor.You can read any data structures book to get grip over single list */

//**************************PACKET SIZE LIST FUNCTIONS**********************//

/*serach for the node */
struct pktsz_node * search_pktsz(struct pktsz_node *front ,int data)
 {
   struct pktsz_node *ptr=NULL;       
   struct pktsz_node *temp=front;
   if(temp==NULL)
       ptr=NULL;
  else
  {
   while(temp)
    {
     if(temp->size==data)
     {
       ptr= temp;
     }
     temp=temp->next;
   }
  }
  return ptr;
}

/*display the list properties*/
/*display the node */
void display_pktsz(struct pktsz_node  *front)
{
  struct pktsz_node  *ptr= front;
  if(!ptr)
    {}    
 /* else
  {
      while(ptr)
      {
         printf("Packet Size :  %d--",ptr->size);
         printf("Count : %d-->",ptr->count);
         if(ptr->next)
             printf("\n");
         ptr=ptr->next;
      }
  }*/
 printf("TOTAL_PACKET_SIZE__COUNT :%d-->",packet_size_count);
 printf("DISTINCT PACKET_SIZE_COUNT :%d\n",packet_size_node_count);
}
  
/* insert the node at the last ,like queue Last in Last out */
/*I have increament packet_size_count on every entry and increamented packet_size_node_count only in case of new unique packet*/
void insert_pktsz(struct pktsz_node **front,int data)
 {
    int id,ret1,ret;
    struct pktsz_node *temp,*ptr,*new;
    new=(struct pktsz_node *) malloc(sizeof(struct pktsz_node)); 
    if(*front==NULL)     /*when list is empty*/
    {
       new->size=data;
       new->count=1;
       new->next=NULL;
       *front=new;
       packet_size_count++;
       packet_size_node_count++;
 
      /*create the thread after initialising the node,pthread_create(...) is standard library function.*/
      id=size_thread_count; 
      ret1=pthread_create(&size_thread[size_thread_count++],NULL,size_function,(void*)&data);
      if(ret1!=0)
       {
           fprintf(stderr,"Error :pthread_create(...)\n");
           exit(1);
       }
      
      //wait till threads are completed ..pthread_join(...) standard function
      ret= pthread_join(size_thread[id],NULL);
      if(ret!=0)
       {
           fprintf(stderr,"Error :pthread_join(...)\n");
           exit(1);
       }
       if(size_thread_count==300000)
              size_thread_count=0;
      } 
    else            /*when list is not empty*/
    {
      temp=*front;
      ptr=search_pktsz(temp,data);   
      if(ptr==NULL)   /*if the node search is not found then a new node is added                        and both packet_size_node_count and packet_size_count is                        increament*/
      {
          new->size=data;
          new->count=1;
          new->next=NULL;
          while(temp->next)
             temp=temp->next;
          temp->next=new;
          packet_size_count++;
          packet_size_node_count++;
        
          //create the thread after initialising the node
          id=size_thread_count;
          ret1=pthread_create(&size_thread[size_thread_count++],NULL,size_function,(void *)&data);
          if(ret1!=0)
          {
              fprintf(stderr,"Error :pthread_create(...)\n");
              exit(1);
          }
      
          //wait till threads are completed ..
          ret= pthread_join(size_thread[id],NULL);
          if(ret!=0)
          {
              fprintf(stderr,"Error :pthread_join(...)\n");
              exit(1);
          }
         if(size_thread_count==300000)
              size_thread_count=0;
       } 
     
    else     /*here search is found and a new node is created but only packet_si               ze_node is incremented not packet_size_node_count*/ 
     { 
          ptr->count++;
          new->size=data;
          new->count=ptr->count;
          new->next=NULL;
          while(temp->next)
             temp=temp->next;
          temp->next=new;
          packet_size_count++;   

           //create the thread after initialising the node
           id=size_thread_count;
           ret1=pthread_create(&size_thread[size_thread_count++],NULL,size_function,(void *)&data);
           if(ret1!=0)
           {
              fprintf(stderr,"Error :pthread_create(...)\n");
              exit(1);
           }
      
           //wait till threads are completed ..
          ret= pthread_join(size_thread[id],NULL);
          if(ret!=0)
          {
               fprintf(stderr,"Error :pthread_join(...)\n");
               exit(1);
          }
         /*it resets the counter of thread_count and by                                   the way using circular linked list is best op                                   tion.*/
         
         if(size_thread_count==300000)
             size_thread_count=0;
     }
   }
 }
/*delete the node from the list.Here I have deleted the first node using the pri nciple FIRST IN FIROUT OUT ,queue implementaion */
int remove_pktsz(struct pktsz_node **front)
{
   struct pktsz_node *temp,*ptr,*prev;
   ptr=*front;
   int ret=0;
   if(*front==NULL)
    {
       ret=0;
    }
    else
    {
                *front=(*front)->next;
                temp=search_pktsz(*front,ptr->size);
                if(temp==NULL)
                 {
                    packet_size_count--;
                    packet_size_node_count--;
                 }
                else
                {
                   temp->count--;
                   packet_size_count--;
                }
                free(ptr);
                ret=1;
                
     }
     return ret;
 }

//ALL LOGIC HERE ARE SAME AS PREVIOUS SIZE LIST DESCRIPTION..................
//*************************SOURCE IP LIST FUNCTION***************************//

/*serach for the node */
struct ips_node* search_ips(struct ips_node *front ,char *str)
 {
   struct ips_node *ptr=NULL;
   struct ips_node *temp=front;
   if(temp==NULL)
    {
      return ptr;
    }
   else
   {
       while(temp)
       {
           if(strcmp(temp->ip,str)==0)
           {
               ptr= temp;
           }
           temp=temp->next;
      }
   return ptr;
  }
}

/*display the node */
void display_ips(struct ips_node  *front)
{
    struct ips_node  *ptr= front;
    if(!ptr)
          {}
  /*  else
    {
       while(ptr)
        {
            printf("IP :  %s--",ptr->ip);
            printf("Count : %d-->",ptr->count);
            if(ptr->next)
                printf("\n");
            ptr=ptr->next;
        }
    }*/
 printf("TOTAL_SOURCE_IP_PACKET_COUNT :%d-->",ips_packet_count);
 printf("DISTINCT_SOURCE_IP_PACKET_COUNT:%d\n",ips_node_count);
}


/*insert node in the list */
void insert_ips(struct ips_node **front,char *str)
 {
    int ret1,id,ret;
    struct ips_node *temp,*ptr,*new;
    new=(struct ips_node *) malloc (sizeof(struct ips_node));
    if(*front==NULL)           /*list is empty */
    {
      memset(new->ip,0,200);
      strcpy(new->ip,str);
      new->count=1;
      new->next=NULL;
      *front=new;
      ips_packet_count++;
      ips_node_count++;
      
      //create the thread after initialising the node
      id=ips_thread_count;
      ret1=pthread_create(&ips_thread[ips_thread_count++],NULL,ips_function,(void *)str);
      if(ret1!=0)
       {
           fprintf(stderr,"Error :pthread_create(...)\n");
           exit(1);
       }
      
      //wait till threads are completed ..
      ret= pthread_join(ips_thread[id],NULL);
      if(ret!=0)
       {
           fprintf(stderr,"Error :pthread_join(...)\n");
           exit(1);
       }
       /*resetting thread counter */
       if(ips_thread_count==300000)
             ips_thread_count=0;
      }
    else         /*list is not empty*/
    {
      temp=*front;                      /*list is not empty*/
      ptr=search_ips(temp,str);
      if(ptr==NULL)
          {
              memset(new->ip,0,200);
              strcpy(new->ip,str);
              new->count=1;
              new->next=NULL;
              while(temp->next)
                   temp=temp->next;
              temp->next=new;
              ips_packet_count++;
              ips_node_count++;
         
      //create the thread after initialising the node
             id=ips_thread_count;
             ret1=pthread_create(&ips_thread[ips_thread_count++],NULL,ips_function,(void *)str);
            if(ret1!=0)
            {
                fprintf(stderr,"Error :pthread_create(...)\n");
                exit(1);
            }
      
      //wait till threads are completed ..
            ret= pthread_join(ips_thread[id],NULL);
            if(ret!=0)
            {
                fprintf(stderr,"Error :pthread_join(...)\n");
                exit(1);
            }
        
         if(ips_thread_count==300000)
              ips_thread_count=0;
        }
      else        /*search is found*/
       {        
           ptr->count++;
           memset(new->ip,0,200);
           strcpy(new->ip,str);
           new->count=ptr->count;
           new->next=NULL;
           while(temp->next)
                 temp=temp->next;
           temp->next=new;
           ips_packet_count++;
      
         //create the thread after initialising the node
            id=ips_thread_count;
            ret1=pthread_create(&ips_thread[ips_thread_count++],NULL,ips_function,(void *)str);
            if(ret1!=0)
            {
                fprintf(stderr,"Error :pthread_create(...)\n");
                exit(1);
            }
      
         //wait till threads are completed ..
          ret= pthread_join(ips_thread[id],NULL);
          if(ret!=0)
           {
               fprintf(stderr,"Error :pthread_join(...)\n");
               exit(1);
           }
          /*resetting counter for the timer*/
         
          if(ips_thread_count==300000)
             ips_thread_count=0;
       }
   }
}

/*delete the first node from the list*/
int remove_ips(struct ips_node **front)
 {
    int ret;
    struct ips_node *temp,*ptr;
    ptr=*front;
    if(*front==NULL)     /*list is empty */
    {
          ret=0;
    } 
    else                 /*list is empty */
    { 
          *front=(*front)->next;
          temp=search_ips(*front,ptr->ip);
          if(temp==NULL)   /*if search not found*/
          {
             ips_packet_count--;
             ips_node_count--;
          }
          else             /*search found */
          {
             temp->count--;
             ips_packet_count--;
          }
          free(ptr);
          ret=1;
      }
     return ret;
 }

//ALL LOGIC HERE ARE SAME AS PREVIOUS SIZE LIST DESCRIPTION..................
//*********************DESTINATION IP LIST FUNCTION***************************//

/*serach for the node */
struct ipd_node* search_ipd(struct ipd_node *front ,char *str)
 {
   struct ipd_node *ptr=NULL;
   struct ipd_node *temp=front;
   if(temp==NULL)
     ptr=NULL;
   while(temp)
   {
     if(strcmp(temp->ip,str)==0)
     {
       ptr= temp;
     }
     temp=temp->next;
   }
  return ptr;
}

/*display the node */
void display_ipd(struct ipd_node  *front)
{
    struct ipd_node  *ptr= front;
    if(!ptr)
    {}
         // printf("Oops !! List is empty :( \n");
   /* else
    {
       while(ptr)
        {
            printf("IP :  %s--",ptr->ip);
            printf("Count : %d-->",ptr->count);
            if(ptr->next)
                printf("\n");
            ptr=ptr->next;
        }
    }*/
 printf("TOTAL_DESTINATION_IP_PACKET_COUNT :%d-->",ipd_packet_count);
 printf("DISTINCT_DESTINATION_IP_PACKET_COUNT:%d\n",ipd_node_count);
}


/*insert node in the list */
void insert_ipd(struct ipd_node **front,char *str)
 {
    int ret1,id,ret;
    struct ipd_node *temp,*ptr,*new;
    new=(struct ipd_node *) malloc (sizeof(struct ipd_node));
    if(*front==NULL)           /*list is empty */
    {
      memset(new->ip,0,200);
      strcpy(new->ip,str);
      new->count=1;
      new->next=NULL;
      *front=new;
      ipd_packet_count++;
      ipd_node_count++;
      
      //create the thread after initialising the node
      id=ipd_thread_count;
      ret1=pthread_create(&ipd_thread[ipd_thread_count++],NULL,ipd_function,(void *)str);
      if(ret1!=0)
       {
           fprintf(stderr,"Error :pthread_create(...)\n");
           exit(1);
       }
      
      //wait till threads are completed ..
      ret= pthread_join(ipd_thread[id],NULL);
      if(ret!=0)
       {
           fprintf(stderr,"Error :pthread_join(...)\n");
           exit(1);
       }
       
         if(ipd_thread_count==300000)
             ipd_thread_count=0;
      }
    else         /*list is not empty*/
    {
      temp=*front;
      ptr=search_ipd(temp,str);
      if(ptr==NULL)
          {
              memset(new->ip,0,200);
              strcpy(new->ip,str);
              new->count=1;
              new->next=NULL;
              while(temp->next)
                   temp=temp->next;
              temp->next=new;
              ipd_packet_count++;
              ipd_node_count++;
         
      //create the thread after initialising the node
             id=ipd_thread_count;
             ret1=pthread_create(&ipd_thread[ipd_thread_count++],NULL,ipd_function,(void *)str);
            if(ret1!=0)
            {
                fprintf(stderr,"Error :pthread_create(...)\n");
                exit(1);
            }
      
      //wait till threads are completed ..
            ret= pthread_join(ipd_thread[id],NULL);
            if(ret!=0)
            {
                fprintf(stderr,"Error :pthread_join(...)\n");
                exit(1);
            }
           
         if(ipd_thread_count==300000)
            ipd_thread_count=0;
        }
      else        /*search is found*/
       {        
           ptr->count++;
           memset(new->ip,0,200); 
           strcpy(new->ip,str);
           new->count=ptr->count;
           new->next=NULL;
           while(temp->next)
                 temp=temp->next;
           temp->next=new;
           ipd_packet_count++;
      
         //create the thread after initialising the node
            id=ipd_thread_count;
            ret1=pthread_create(&ipd_thread[ipd_thread_count++],NULL,ipd_function,(void *)str);
            if(ret1!=0)
            {
                fprintf(stderr,"Error :pthread_create(...)\n");
                exit(1);
            }
      
         //wait till threads are completed ..
          ret= pthread_join(ipd_thread[id],NULL);
          if(ret!=0)
           {
               fprintf(stderr,"Error :pthread_join(...)\n");
               exit(1);
           }
         
         if(ipd_thread_count==300000)
             ipd_thread_count=0;
       }
   }
}

/*delete the first node from the list*/
int remove_ipd(struct ipd_node **front)
 {
    int ret;
    struct ipd_node *temp,*ptr;
    ptr=*front;
    if(*front==NULL)     /*list is empty */
    {
          ret=0;
    } 
    else                 /*list is empty */
    { 
          *front=(*front)->next;
          temp=search_ipd(*front,ptr->ip);
          if(temp==NULL)   /*if search not found*/
          {
             ipd_packet_count--;
             ipd_node_count--;
          }
          else             /*search found */
          {
             temp->count--;
             ipd_packet_count--;
          }
          free(ptr);
          ret=1;
     }
    return ret;
  }


//ALL LOGIC HERE ARE SAME AS PREVIOUS SIZE LIST DESCRIPTION..................
//*********************SOURCE PORT LIST FUNCTION*****************************//

/*search function */
struct sport_node *search_sport(struct sport_node *front,char *str,int data)
{
   struct sport_node *ptr=NULL;
   struct sport_node *temp=front;
   if(temp==NULL)
    ptr=NULL;
   else
   {
   while(temp)
   {
     if((strcmp(temp->ip,str)==0)&&(temp->port==data))
     {
       ptr= temp;
     }
     temp=temp->next;
   }
  }
  return ptr;
}


/*display the node */
void display_sport(struct sport_node  *front)
{
    struct sport_node  *ptr= front;
    if(!ptr)
    {}
    //      printf("Oops !!Source port  List is empty :( \n");
  /*  else
    {
       while(ptr)
        {
            printf("IP :  %s--",ptr->ip);
            printf("Count : %d--",ptr->count);
            printf("Port  : %d-->",ptr->port);
            if(ptr->next)
                printf("\n");
            ptr=ptr->next;
        }
    }*/
 printf("TOTAL_SOURCE_PORT_PACKET_COUNT :%d-->",sport_packet_count);
 printf("DISTINCT_SOURCE_PORT_PACKET_COUNT:%d\n",sport_node_count);
}


/*insert node in the list */
void insert_sport(struct sport_node **front,char *str,int data)
 {
    int ret1,id,ret;
    struct sport_node *temp,*ptr,*new;
    new=(struct sport_node *) malloc (sizeof(struct sport_node));
    if(*front==NULL)           /*list is empty */
    {
      memset(new->ip,0,200);
      strcpy(new->ip,str);
      new->count=1;
      new->port=data;
      new->next=NULL;
      *front=new;
      sport_packet_count++;
      sport_node_count++;
      
      //create the thread after initialising the node
      id=sport_thread_count;
      ret1=pthread_create(&sport_thread[sport_thread_count++],NULL,sport_function,(void *)str);
      if(ret1!=0)
       {
           fprintf(stderr,"Error :pthread_create(...)\n");
           exit(1);
       }
      
      //wait till threads are completed ..
      ret= pthread_join(sport_thread[id],NULL);
      if(ret!=0)
       {
           fprintf(stderr,"Error :pthread_join(...)\n");
           exit(1);
       }
     
       if(sport_thread_count==300000)
            sport_thread_count=0;
      }
    else         /*list is not empty*/
    {
      temp=*front;
      ptr=search_sport(temp,str,data);
      if(ptr==NULL)
          {
              memset(new->ip,0,200);
              strcpy(new->ip,str);
              new->count=1;
              new->port=data;
              new->next=NULL;
              while(temp->next)
                   temp=temp->next;
              temp->next=new;
              sport_packet_count++;
              sport_node_count++;
         
      //create the thread after initialising the node
             id=sport_thread_count;
             ret1=pthread_create(&sport_thread[sport_thread_count++],NULL,sport_function,(void *)str);
            if(ret1!=0)
            {
                fprintf(stderr,"Error :pthread_create(...)\n");
                exit(1);
            }
      
      //wait till threads are completed ..
            ret= pthread_join(sport_thread[id],NULL);
            if(ret!=0)
            {
                fprintf(stderr,"Error :pthread_join(...)\n");
                exit(1);
            }
          
         if(sport_thread_count==300000)
           sport_thread_count=0;
        }
      else        /*search is found*/
       {        
           ptr->count++;
           memset(new->ip,0,200);
           strcpy(new->ip,str);
           new->count=ptr->count;
           new->port=data;
           new->next=NULL;
           while(temp->next)
                 temp=temp->next;
           temp->next=new;
           sport_packet_count++;
      
         //create the thread after initialising the node
            id=sport_thread_count;
            ret1=pthread_create(&sport_thread[sport_thread_count++],NULL,sport_function,(void *)str);
            if(ret1!=0)
            {
                fprintf(stderr,"Error :pthread_create(...)\n");
                exit(1);
            }
      
         //wait till threads are completed ..
          ret= pthread_join(sport_thread[id],NULL);
          if(ret!=0)
           {
               fprintf(stderr,"Error :pthread_join(...)\n");
               exit(1);
           }
         
         if(sport_thread_count==300000)
              sport_thread_count=0;
       }
   }
}

/*delete the first node from the list*/
int remove_sport(struct sport_node **front)
 {
    int ret;
    struct sport_node *temp,*ptr;
    ptr=*front;
    if(*front==NULL)     /*list is empty */
    {
          ret=0;
    } 
    else                 /*list is empty */
    { 
          *front=(*front)->next;
          temp=search_sport(*front,ptr->ip,ptr->port);
          if(temp==NULL)   /*if search not found*/
          {
             sport_packet_count--;
             sport_node_count--;
          }
          else             /*search found */
          {
             temp->count--;
             sport_packet_count--;
          }
          free(ptr);
          ret=1;
     }
     return ret;
  }


//ALL LOGIC HERE ARE SAME AS PREVIOUS SIZE LIST DESCRIPTION..................
//*****************DESTINATION PORT LIST FUNCTION*****************************//

/*search function */
struct dport_node *search_dport(struct dport_node *front,char *str,int data)
{
   struct dport_node *ptr=NULL;
   struct dport_node *temp=front;
   if(temp==NULL)
   {
      ptr=NULL;
   }
  else
   {
   while(temp)
   {
     if((strcmp(temp->ip,str)==0)&&(temp->port==data))
     {
       ptr= temp;
     }
     temp=temp->next;
   }
  }
  return ptr;
}


/*display the node */
void display_dport(struct dport_node  *front)
{
    struct dport_node  *ptr= front;
    if(!ptr)
    {}
        //  printf("Oops !! List is empty :( \n");
  /*  else
    {
       while(ptr)
        {
            printf("IP :  %s--",ptr->ip);
            printf("Count : %d--",ptr->count);
            printf("Port  : %d-->",ptr->port);
            if(ptr->next)
                printf("\n");
            ptr=ptr->next;
        }
    }*/
 printf("TOTAL_DESTINATION_PORT_PACKET_COUNT :%d-->",dport_packet_count);
 printf("DISTINCT_DESTINATION_PORT_PACKET_COUNT:%d\n",dport_node_count);
}


/*insert node in the list */
void insert_dport(struct dport_node **front,char *str,int data)
 {
    int ret1,id,ret;
    struct dport_node *temp,*ptr,*new;
    new=(struct dport_node *) malloc (sizeof(struct dport_node));
    if(*front==NULL)           /*list is empty */
    {
      memset(new->ip,0,200);
      strcpy(new->ip,str);
      new->count=1;
      new->port=data;
      new->next=NULL;
      *front=new;
      dport_packet_count++;
      dport_node_count++;
      
      //create the thread after initialising the node
      id=dport_thread_count;
      ret1=pthread_create(&dport_thread[dport_thread_count++],NULL,dport_function,(void *)str);
      if(ret1!=0)
       {
           fprintf(stderr,"Error :pthread_create(...)\n");
           exit(1);
       }
      
      //wait till threads are completed ..
      ret= pthread_join(dport_thread[id],NULL);
      if(ret!=0)
       {
           fprintf(stderr,"Error :pthread_join(...)\n");
           exit(1);
       }
       
       if(dport_thread_count==300000)
           dport_thread_count=0;
      }
    else         /*list is not empty*/
    {
      temp=*front;
      ptr=search_dport(temp,str,data);
      if(ptr==NULL)
          {
              memset(new->ip,0,200);
              strcpy(new->ip,str);
              new->count=1;
              new->port=data;
              new->next=NULL;
              while(temp->next)
                   temp=temp->next;
              temp->next=new;
              dport_packet_count++;
              dport_node_count++;
         
      //create the thread after initialising the node
             id=dport_thread_count;
             ret1=pthread_create(&dport_thread[dport_thread_count++],NULL,dport_function,(void *)str);
            if(ret1!=0)
            {
                fprintf(stderr,"Error :pthread_create(...)\n");
                exit(1);
            }
      
      //wait till threads are completed ..
            ret= pthread_join(dport_thread[id],NULL);
            if(ret!=0)
            {
                fprintf(stderr,"Error :pthread_join(...)\n");
                exit(1);
            }
          
         if(dport_thread_count==300000)
              dport_thread_count=0;
        }
      else        /*search is found*/
       {   
           ptr->count++;
           memset(new->ip,0,200);     
           strcpy(new->ip,str);
           new->count=ptr->count;
           new->port=data;
           new->next=NULL;
           while(temp->next)
                 temp=temp->next;
           temp->next=new;
           dport_packet_count++;
      
         //create the thread after initialising the node
            id=dport_thread_count;
            ret1=pthread_create(&dport_thread[dport_thread_count++],NULL,dport_function,(void *)str);
            if(ret1!=0)
            {
                fprintf(stderr,"Error :pthread_create(...)\n");
                exit(1);
            }
      
         //wait till threads are completed ..
          ret= pthread_join(dport_thread[id],NULL);
          if(ret!=0)
           {
               fprintf(stderr,"Error :pthread_join(...)\n");
               exit(1);
           }
          
         if(dport_thread_count==300000)
              dport_thread_count=0;
       }
   }
}

/*delete the first node from the list*/
int remove_dport(struct dport_node **front)
 {
    int ret;
    struct dport_node *temp,*ptr;
    ptr=*front;
    if(*front==NULL)     /*list is empty */
    {
          ret=0;
    } 
    else                 /*list is empty */
    { 
          *front=(*front)->next;
          temp=search_dport(*front,ptr->ip,ptr->port);
          if(temp==NULL)   /*if search not found*/
          {
             dport_packet_count--;
             dport_node_count--;
          }
          else             /*search found */
          {
             temp->count--;
             dport_packet_count--;
          }
          free(ptr);
          ret=1;
     }
    return ret;
  }

//********************************ARP FUNCTION*******************************//
/*void display_arp()
{
   printf("TOTAL NUMBER OF ARP PACKET :%d\n",arp_packet_count);
} */  



//********************************MAIN FUNCTION******************************//
int main()
{
   int i,ret,count=1,n,len,sport,dport;
   char add[200],sip[200],dip[200];
   char *dev,*net,*mask,errbuf[PCAP_ERRBUF_SIZE];  
   char devs[100][100];/*array containing list of all the device*/
   pcap_if_t *alldevice,*device;  /*strcuture containing device parameters*/
   pcap_t *descr;    /*pcap descriptor*/
   const u_char *packet; /*pointer for the packet */
   u_char *ptr;          
   bpf_u_int32 netp;    /*variable for giving the ip address of the machine*/
   bpf_u_int32 maskp;   /*variable for giving the netmask of the machine */
   struct in_addr addr; /*structure for network address */
   struct pcap_pkthdr hdr;/*structure for the packet header*/
   struct ether_header *eptr=NULL;/*structure for ethernet header*/
   struct ip *iphdr=NULL; /*structure for IPv4 header*/
   struct arp_header *arphdr=NULL; /*structure for ARP Header */
   struct tcp_header *tcphdr1=NULL; /*self made structure for tcp header stru                                        -cture*/
   struct tcphdr *tcphdr2=NULL; /*default structure for tcp header*/
   struct udphdr *udphdr1=NULL;  /*defalut structure for udp header*/
   time_t rawtime;               /*varible defined in time.h used to get present time */
   struct tm *timeinfo;          /*structure used to get current time */ 
   FILE *logfile;       


   /*getting all the devices available*/
   printf("Finding all the devices ...\n");
   ret=pcap_findalldevs(&alldevice,errbuf); /*function that find all the opening                                             port for packet caputuring*/
   if(ret==-1)
    {
      fprintf(stderr,"Error:pcap_findalldevs(...):%s\n",errbuf);
      exit(1);
    }
   
    //displaying all the devices available
    printf("Displaying availabe devices :\n");
    for(device=alldevice;device!=NULL;device=device->next)
     {
        printf("%d.%s--  %s\n",count++,device->name,device->description);
        if(device->name !=NULL)
         { 
              strcpy(devs[count],device->name);
         }
     }
   /*asking user to select the device */
     /* printf("Select the number of the device on which to sniff\n");
      scanf("%d",&n);
      dev=devs[n];*/
    dev=pcap_lookupdev(errbuf);      /*look for the available devices*/
    if(dev==NULL)
     {
        fprintf(stderr,"Error:pcap_lookupdev(...):%s\n",errbuf);
        exit(1);
     }

   /*getting information of netmast and ip of the host */
    ret=pcap_lookupnet(dev,&netp,&maskp,errbuf);  /*look for the ip and mask for                                                   the capturing device*/
    if(ret==-1)
    {  
       fprintf(stderr,"Error:pcap_lookupnet(...):%s\n",errbuf);
    }
    
    addr.s_addr=netp;
    net=inet_ntoa(addr);          /*convert strcuture into readable string*/
    if(net==NULL)
     {
        perror("inet_ntoa");
     }
     printf("NET: %s\n",net);
     
     addr.s_addr=maskp;
     mask=inet_ntoa(addr);
     if(mask==NULL)
      {
         perror("inet_ntoa");
      }
     printf("MASK: %s\n",mask);
     
    
   /*opening device to sniff*/
   printf("opening device %s for packet capturing...\n",dev);
   descr=pcap_open_live(dev,65536,0,-1,errbuf); /*opening device for capturing*/
   if(descr==NULL)
    {
       fprintf(stderr,"Error:pcap_open_live(...):%s\n",errbuf);
       exit(1);
    }
    
    /*opening a file to fill the captured information*/
    logfile=fopen("log.txt","w");
    if(logfile==NULL)
    {
        fprintf(stderr,"Error:unable to create log  file\n");
    }
    char str2[]="print timer";
    makeTimer(str2,&print_timer[print_timer_count++],expireTime,intervalTime);/*initaiting timerto                                                              display result*/
    if(print_timer_count==300000)
           print_timer_count=0;             /*resetting counter */
     time(&rawtime);
     timeinfo=localtime(&rawtime);
     printf("Starting Packet Capturing using device %s\n",dev); 
     printf("********************CAPTURING START AT %s\n",asctime(timeinfo));
     while(1)
     {
      ret = pcap_setnonblock(descr,0,errbuf);  /*it is required for pcap_next()*/
      if(ret==-1)
     {
        fprintf(stderr,"Error:pcap_setnonblock(...):%s\n",errbuf);
        exit(1);
     }

    packet=pcap_next(descr,&hdr);  /*handle packet captured*/
    if(packet==NULL)
     { 
        fprintf(stderr,"Error:pcap_next(...):unable to grab the packet\n");
        exit(1);
     }
     len=hdr.len;
     insert_pktsz(&front_pktsz,len);  /*inerting packet in the list*/
     /*to get the current timestamp */
     sprintf(date,"%s\n",ctime((const time_t *)&hdr.ts.tv_sec));      
     eptr=(struct ether_header *)packet;/*gettting ethernet header*/
     if(ntohs(eptr->ether_type)==ETHERTYPE_IP) /*check for IP Packet*/
     {
            iphdr=(struct ip *)(packet +14);      /*extract IP Header from the I                                                   P Header*/
            memset(dip,0,200);                    /*flusing the add */
            strcpy(dip,inet_ntoa(iphdr->ip_dst)); /*copying destination IP to th                                                   e string add*/
            insert_ipd(&front_ipd,dip);           /*inserting Destination IP to                                                     the destination IP list*/
            bzero(sip,200);                       /*flushing the add*/
            strcpy(sip,inet_ntoa(iphdr->ip_src)); /*extracting the Source IP fro                                                   m the from IP Header*/
            insert_ips(&front_ips,sip);           /*inserting the Destination IP                                                  into the Destination IP list*/
            
            switch(iphdr->ip_p)
             {
                 case IPPROTO_TCP :
                    tcphdr2=(struct tcphdr *)(packet +14+20);
                    tcphdr1=(struct tcp_header *)(packet +14+20);
                    sport=tcphdr2->source;
                    insert_sport(&front_sport,sip,sport);
                    dport=tcphdr2->dest;
                    insert_dport(&front_dport,dip,dport);
                    break;
                 case IPPROTO_UDP :
                    udphdr1=(struct udphdr *)(packet +14+20);
                    sport=udphdr1->source;
                    insert_sport(&front_sport,sip,sport);
                    dport=udphdr1->dest;
                    insert_dport(&front_dport,dip,dport);
                    break;
                 default :
                    break;
             }

      }

     if(ntohs(eptr->ether_type)==ETHERTYPE_ARP) /*check for ARP Packet*/
     { 
        arp_packet_count++;                    /*incrementing ARP packet count*/
        arphdr=(struct arp_header *)(packet + 14);/*extracting header of the ARP                                                   Packet*/
        memset(add,0,200);                    /*flushing the add variable*/
        sprintf(add,"%d.%d.%d.%d",arphdr->spa[0],arphdr->spa[1],arphdr->spa[2],arphdr->spa[3]);                 /*copying the source  IP from arp header */          
        insert_ips(&front_ips,add);/*inserting the source IP in Source IP list*/
        memset(add,0,200);    /*flushing the add variable*/  
        sprintf(add,"%d.%d.%d.%d",arphdr->dpa[0],arphdr->dpa[1],arphdr->dpa[2],arphdr->dpa[3]);              /*copying the Destination IP in the Destination IP
                               list*/
        insert_ipd(&front_ipd,add); /*inserting the Destination IP in the Destin                                     -ation IP list*/
     }     

    }
    return 0;
 }

