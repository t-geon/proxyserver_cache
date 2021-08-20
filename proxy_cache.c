//////////////////////////////////////////////
// Os		: Ubuntu 16.04 LTS 64bits		//
// Author	: KIm taek geon					//
////////////////////////////////////////////// 

#include <stdio.h>		//sprintf()
#include <string.h>		//strcpy(), strlen()
#include <openssl/sha.h>	//SHA1()
#include <sys/types.h>		//getpwuid(), fork(), getpid(), getppid()
#include <unistd.h>		//getuid(), getppid()
#include <pwd.h>		//pw_dir
#include <sys/stat.h>		//S_IRWXU , S_IRWXG , S_IRWXO
#include <fcntl.h> 		//creat()
#include <time.h>		//localtime(), ctime()
#include <dirent.h>		//opendir(),readdir(),rewinddir()
#include <sys/wait.h>		//wait()
#include <stdlib.h>		//exit()
#include <sys/socket.h>		//socket functions
#include <netinet/in.h>		//
#include <arpa/inet.h>		//inet_ntoa()	
#include <netdb.h>
#include <signal.h>		//signal()
#include <unistd.h>		//alarm(), sleep()
#include <sys/ipc.h>		//semop, semctl, semget
#include <sys/sem.h>		//SEM_UNDO, SETVAL
#include <pthread.h>		//pthread_create(), pthread_join()

#define BUFFSIZE	30000//1024
#define PORTNO		38030
pid_t parpid;
time_t now;
int subnum;			//child process count
int w;				//log write
char inputurl[BUFFSIZE];	//input url 
char inputurlfile[BUFFSIZE];	//input url cache file path
char checkurl[BUFFSIZE];
int firstcheck;	

//////////////////////////////////////////////////////////
// sha1_hash											//
// =====================================================//
// Input: char* input_url : input url					//
//		hashed_url : result url (changed url)			//
// Output: char* hashed_url : changed url				//
// Purpose: input_url hashing							//
//////////////////////////////////////////////////////////

char *sha1_hash(char *input_url, char *hashed_url){
	unsigned char hashed_160bits[20];	//hashed value(160 bits)
	char hashed_hex[41];			
	int i;

	SHA1(input_url,strlen(input_url),hashed_160bits);//Hashed input_url

	for(i=0;i<sizeof(hashed_160bits);i++)
		sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);//Character string expressing 1 byte of hash 160 bits in hexadecimal

	strcpy(hashed_url,hashed_hex);// copy hashed_hex to hashed_url

	return hashed_url;
}


//////////////////////////////////////////////////////////
// getHOmeDir											//
// =====================================================//
// Input: char* home : result storage variable			//
// Output: char* home : result home path				//
// Purpose: Get home path								//
//////////////////////////////////////////////////////////

char *getHomeDir(char *home){

	struct passwd *usr_info=getpwuid(getuid());	//Receive details about your account with uid
	strcpy(home,usr_info->pw_dir);	//Get home directory with account details and pw_dir

	return home;

}

//////////////////////////////////////////////////////////
// getIPAddr											//
// =====================================================//
// Input: char* addr : host name						//
// Output: char* haddr : network address of host		//
// Purpose: network address of host						//
//////////////////////////////////////////////////////////
char* getIPAddr(char* addr) {
	struct hostent* hent;
	char* haddr;
	int l = strlen(addr);
	if ((hent = (struct hostent*)gethostbyname(addr)) != NULL){
		haddr = inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));
	}
	return haddr;
}

//////////////////////////////////////////////////////////
// alarmhandler											//
// =====================================================//
// Input: int sig : signal number						//
// Purpose: alarm handling								//
//////////////////////////////////////////////////////////
void alarmhandler(int sig){
	printf("\nNo response\n"); //print error message
	pid_t child;			//get child pid
	child=getpid();			//get child pid
	printf("%d child process kill\n",child);
	kill(child,SIGKILL);		//child process kill, signal generation
}

//////////////////////////////////////////////////////////
// childhandler											//
// =====================================================//
// Input: int sig : signal number						//
// Purpose: change in status of child handling			//
//////////////////////////////////////////////////////////
void childhandler(int sig){
	int status;
	pid_t child;
	while((child=waitpid(-1,&status,WNOHANG))>0){
	//	printf("%d child process exit\n",child);
	}
}

//////////////////////////////////////////////////////////
// stophandler											//
// =====================================================//
// Input: int sig : signal number						//
// Purpose: change in status of child handling			//
//////////////////////////////////////////////////////////
void stophandler(int sig){
	if(getpid()==parpid){
		char logt[]="./logfile/logfile.txt";	//logfile path
		char terminated[100];
		time_t end;				//save end time
		time(&end);
		FILE* out1=fopen(logt,"at");		//open logfile
		sprintf(terminated,"**SERVER** [Terminated] run time: %ld sec. #sub process : %d\n",end-now,subnum);		//make terminated string
		fputs(terminated, out1);		//write Terminated
		fclose(out1);
		exit(0);
	}	
}

//////////////////////////////////////////////////////////
// p													//
// =====================================================//
// Input: int semid : semaphore id						//
// Purpose: semaphore value -1							//
//////////////////////////////////////////////////////////
void p(int semid){
	struct sembuf pbuf;
	pbuf.sem_num=0;
	pbuf.sem_op=-1;
	pbuf.sem_flg=SEM_UNDO;	//Set up adjust on exit entry.
	if((semop(semid,&pbuf,1))==-1){//semaphore down
		perror("p : semop failed");	//error
		exit(1);
	}
}

//////////////////////////////////////////////////////////
// v													//
// =====================================================//
// Input: int semid : semaphore id						//
// Purpose: semaphore value +1							//
//////////////////////////////////////////////////////////
void v(int semid){
	struct sembuf vbuf;
	vbuf.sem_num=0;
	vbuf.sem_op=1;
	vbuf.sem_flg=SEM_UNDO;	//Set up adjust on exit entry.
	if((semop(semid,&vbuf,1))==-1){////semaphore up
		perror("p : semop failed");	//error
		exit(1);
	}
}

//////////////////////////////////////////////////////////
// thr_fn												//
// =====================================================//
// Input: void* buf : Transfer factor					//
// Purpose: Print that a thread has been created		//
//////////////////////////////////////////////////////////
void *thr_fn(void* buf){
	printf("*PID# %d create the *TID# %lu. \n",getpid(),pthread_self());//print create message
}

int main(){
	pid_t pid,tpid;			//process ID
	int hm=0,find=0;//hit is 1, miss is 0, first time is miss, find is same name directory
	char home[100],dirname[100],finame[100];//directory path, file path
	char hashed[100];			//save hashed url
	char cache[]="/cache",sl[]="/";		//char to make a path
	char n1[4];				//directory name
	char f[100];				//file name
	char log_txt[]="./logfile/logfile.txt";	//logfile path
	char ti[100];				//time string
	struct dirent *d;			//directory entry
	DIR *dp;				//directory position pointer

	int err;		//error check
	void *tret;		//contains the exit status of the target thread
	pthread_t tid;		//thread id

	int semid, i;
	union semun{
		int val;	//Use as a value for SETVAL
		struct semid_ds *buf;	//buf of IPC_STAT, IPC_SET
		unsigned short int *array;	//intruction array
	}arg;

	parpid=getpid();
	getHomeDir(home);			//call function
	strcat(home,cache);			//String concatenation
	mkdir(home, S_IRWXU | S_IRWXG | S_IRWXO);	//create cache directory(777)
	strcat(home,sl);

	mkdir("logfile", S_IRWXU | S_IRWXG | S_IRWXO);//create logfile
	creat(log_txt,0666);			//log file creat

	struct sockaddr_in p_server_addr,client_addr,server_addr;
	int client_fd, proxy_fd, server_fd;
	int len, len_out;						//save message length
	char *hostname =(char*)malloc(sizeof(char) * 100);		//save host name
	char * ipaddr=NULL;						//save ip address
	struct hostent* hent;

	//semaphore creat
	if((semid = semget((key_t)38030,1,IPC_CREAT|0666))==-1){//get semaphore
		perror("semget failed");//print error
		exit(1);	//error exit
	}

	arg.val=1;
	if((semctl(semid,0,SETVAL,arg))==-1){	//semaphore set value
		perror("semctl failed");	//error print
		exit(1);
	}

	if((proxy_fd=socket(PF_INET, SOCK_STREAM,0))<0){		//socket creat
		printf("Server : Can't open stream socket\n");		//error print
		return 0;	//program end
	}

	int opt=1;
	setsockopt(proxy_fd,SOL_SOCKET,SO_REUSEADDR,&opt, sizeof(opt));	//bind() error clear

	bzero((char*)&p_server_addr,sizeof(p_server_addr));	//initialization
	p_server_addr.sin_family=AF_INET;			//sin_family init
	p_server_addr.sin_addr.s_addr=htonl(INADDR_ANY);	//sin_address init
	p_server_addr.sin_port=htons(PORTNO);			//sin_port init
	
	if(bind(proxy_fd,(struct sockaddr*)&p_server_addr,sizeof(p_server_addr))<0){//socket connect
		printf("Server : Can't bind local address\n");
		return 0;	//program end
	}

	listen(proxy_fd, 5);		//server Ready to receive(5)

	//signal handler define	
	signal(SIGALRM,alarmhandler);	//SIGALRM handler
	signal(SIGCHLD,childhandler);	//SIGCHLD handler
	signal(SIGINT,stophandler);	//SIGINT handler

	time(&now);			//get current time

	while(1){
		struct in_addr inet_client_address;		
		char buf[BUFFSIZE]={0,};		//save request,response
		char tmp[BUFFSIZE]={0,};		//save request
		char method[20]={0,};			//using get url
		char url[BUFFSIZE]={0,};		//save url
		char mainurl[BUFFSIZE]={0,};		//save main url
		char *tok=NULL;				

		len=sizeof(client_addr);	//client address length
		client_fd=accept(proxy_fd,(struct sockaddr*)&client_addr, &len);//request accept

		if(client_fd<0){	//error
			printf("Server : accept failed    %d\n",getpid());
			return 0;		
		}

		inet_client_address.s_addr =client_addr.sin_addr.s_addr;
		
		if((len_out=read(client_fd, buf, BUFFSIZE))<0){
			return 0;
		}
		strcpy(tmp,buf);

		//get URL
		tok=strtok(tmp, " ");
		strcpy(method, tok);	//method field
		if(strcmp(method, "GET")==0){	//method==GET
			tok=strtok(NULL, " ");
			strcpy(url,tok);	//save URL
		}
		sha1_hash(url,hashed);	//Save hased URL in hased

		//get cache data directory name
		strncpy(n1,hashed,3);		//front 3 text
		n1[3]=0;			//n1[4]=NULL(end string)
		strcpy(dirname,home);		//make new path
		strcat(dirname,n1);

		strncpy(f,&hashed[3],sizeof(hashed)-3);	//From the 3rd 	to the end of the string

		//get cache data file name
		strcpy(finame,dirname);
		strcat(finame,sl);
		strcat(finame,f);

		//Check hit and miss.
		hm=0;	//If this cannot find the same name, hm=0
		if((dp=opendir(home))==NULL){return 0;}

		//Find a directory with the same name
		while(d=readdir(dp)){		//read directory entry
			if(d->d_ino !=0){	//If there is a file
				if(strcmp(d->d_name,n1)==0){	//same name
					find=1;
					break;
				}			
			}
		}

		//Find files with the same name
		if(find==1){		//there is same name directory
			strcat(dirname,sl);
			dp=opendir(dirname);
			while(d=readdir(dp)){	//read directory entry
				if(d->d_ino !=0)	//If there is a file
				if(strcmp(d->d_name,f)==0){	//same name
				hm=1;
				break;
				}
			}			
		}
		else{hm=0;}
		find=0;
		
		//get host name
		char tr[BUFFSIZE];
		if(strstr(buf,"Host: ") != NULL) {
			strcpy(tr,strstr(buf,"Host: "));
			strtok(tr,"\r\n");
			strtok(tr," ");
			strcpy(hostname,strtok(NULL," "));
		}

		//Processing to receive only the output for the entered url
		int strcheck[10]={0,};	//input url check
		strcheck[0]=strncmp(hostname,"detectportal",12);
		strcheck[1]=strncmp(hostname,"incoming",8);
		strcheck[2]=strncmp(hostname,"push",4);
		strcheck[3]=strncmp(hostname,"shavar",6);
		strcheck[4]=strncmp(hostname,"safebrowsing",12);
		strcheck[5]=strncmp(hostname,"snippets",8);
		strcheck[6]=strncmp(hostname,"firefox",7);
		strcheck[7]=strncmp(hostname,"content",7);
		char*ptr=strchr(hostname,':');
		if(ptr==NULL){strcheck[8]=-1;}
		else{strcheck[8]=strncmp(ptr,":443",4);}

		if(strcheck[0]!=0&&strcheck[1]!=0&&strcheck[2]!=0&&strcheck[3]!=0&&strcheck[4]!=0&&strcheck[5]!=0&&strcheck[6]!=0&&strcheck[7]!=0&&strcheck[8]!=0){
		
			//get main url( ~~~ of http://~~~~/)
			char* tt=NULL;
			strcpy(tok,url);
			tt=strtok(tok, "/");
			tt=strtok(NULL, "/");	
			strcpy(mainurl,tt);

			if(firstcheck==0){		//first url
				//printf("\n=====first url=====\n");
				strcpy(inputurl,url);
				strcpy(checkurl,mainurl);
				strcpy(inputurlfile,finame);
				firstcheck=1;
				w=1;		
				subnum++;
			}
			else if(strcmp(inputurl,url)==0){	//same url
				//printf("\n=====same url=====\n");
				w=1;
			}
			else if(strstr(url,checkurl)!=NULL||strstr(url,".png")!=NULL){	//not input url
				//printf("\n=====not input url=====\n");
				w=0;
			}
			else{	//new input url
				//printf("\n=====new url=====\n");
				strcpy(inputurl,url);
				strcpy(checkurl,mainurl);
				strcpy(inputurlfile,finame);
				w=1;
				subnum++;
			}
//puts(buf);
		}

		//child process create
		pid=fork();
		if(pid==-1){
			close(client_fd);
			close(proxy_fd);
			continue;
		}

		if(pid==0){	//child process
			//HIT
			if(hm==1){
			if(strstr(url,inputurl)!=NULL||strstr(url,".png")!=NULL){
				//cache file read
				char buffer[BUFFSIZE]={0,};
				int fd=open(finame,O_RDONLY);
				len=read(fd,buffer,BUFFSIZE);
				close(fd);
				
				printf("*PID# %d is waiting for the semaphore. \n",getpid());
				p(semid);	//semaphore value -1
				printf("*PID# %d is in the critical zone. \n",getpid());
				//Send response to client
				if((len=write(client_fd, buffer, len))<0){
					printf("\nerror\n");
				}
				//log file write
				if(strstr(url,"favicon")==NULL&&strcmp(url,inputurl)==0&&firstcheck==1&&w==1){
					err=pthread_create(&tid, NULL,thr_fn, NULL);	//thread creat
					if(err!=0){//error check
						printf("pthread_create() error.\n");	//print error message
						return 0;
					}

					//make time string
					time_t logtime;
					struct tm *lt;
					time(&logtime);
					lt=localtime(&logtime);
					strftime(ti,100,"-[%Y/%m/%d, %T]\n",lt);
				
					//make HIT hashed string
					FILE* out1=fopen(log_txt,"at");
					char str[100];
					strcpy(str,"[HIT] ");
					strncat(str,&finame[25],sizeof(finame)-25);
					strcat(str,ti);	
					fputs(str, out1);
			
					//make HIT url string
					str[0]='\0';
					strcpy(str,"[HIT] ");	
					strcat(str,url);	
					strcat(str,"\n");	
					fputs(str, out1);	
					fclose(out1);	//close logfile
					w=0;
					
					//print message when thread is terminated
					if(pthread_join(tid,&tret)==0){	//waiting for tid thread termination
						printf("*TID# %lu is exitis exited. \n",tid);
					}
				}
				printf("*PID# %d exited the critical zone. \n",getpid());
				v(semid);	//semaphore value +1

				bzero(buffer,sizeof(buffer));
			}
			}//HIT end

			//MISS
			else if(hm==0){
				ipaddr=getIPAddr(hostname);//get ip address

				//soacket create
				if((server_fd=socket(PF_INET, SOCK_STREAM,0))<0){
					printf("Server : Can't open stream socket\n");
					return 0;
				}
	
				bzero((char*)&server_addr,sizeof(server_addr));
				server_addr.sin_family=AF_INET;		
				server_addr.sin_port=htons(80);
				server_addr.sin_addr.s_addr=inet_addr(ipaddr);

				//server connect
				if(connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr))<0) {
                                       	printf("Server : Can't connect");
					return 0;
                              	}

				//forwarding request
				if((len_out=write(server_fd,buf,len_out))<0){
					printf("error");
				}
				alarm(60);	//alarm start

				char response_message[BUFFSIZE]={0,};
				
				printf("*PID# %d is waiting for the semaphore. \n",getpid());
				p(semid);	//semaphore value -1
				printf("*PID# %d is in the critical zone. \n",getpid());
//sleep(5);
				//log file write
				if(strstr(url,"favicon")==NULL&&strcmp(url,inputurl)==0&&firstcheck==1&&w==1){
					err=pthread_create(&tid, NULL,thr_fn, NULL);	//thread creat
					if(err!=0){//error check
						printf("pthread_create() error.\n");	//print error message
						return 0;
					}

					//make time string		
					time_t logtime;
					struct tm *lt;
					time(&logtime);
					lt=localtime(&logtime);
					strftime(ti,100,"-[%Y/%m/%d, %T]\n",lt);

					//make url string
					char str[100];
					strcpy(str,"[MISS] ");	
					strcat(str,url);	
					strcat(str,ti);	

					FILE* out=fopen(log_txt,"at");
					fputs(str, out);	//url_string write
					subnum++;		//child process count
					fclose(out);
					w=0;

					//print message when thread is terminated
					if(pthread_join(tid,&tret)==0){	//waiting for tid thread termination
						printf("*TID# %lu is exitis exited. \n",tid);
					}
				}

				//response message read
				if((len=read(server_fd,response_message,BUFFSIZE))>0){
					if(strcmp(url,inputurl)==0||(strstr(url,inputurl)==NULL&&strstr(url,".png")==NULL)){//new cache file
						mkdir(dirname, S_IRWXU | S_IRWXG | S_IRWXO);
						creat(finame,0666);	//create file

						//save response 
						int fd=open(finame,O_WRONLY);
						write(fd,response_message,len);
						close(fd);
					}

					else if(firstcheck==1){	//input cache file write
						int fd=open(inputurlfile,O_WRONLY);
						lseek(fd,0,SEEK_END);		//append
						write(fd,response_message,len);
						close(fd);
					}

					//forwarding response message
					if((len=write(client_fd,response_message,len))<0){
						printf("error\n");
					}
					bzero(buf,sizeof(buf));
					bzero(response_message,sizeof(response_message));
				}//read end
				printf("*PID# %d exited the critical zone. \n",getpid());
				v(semid);	//semaphore value +1
				close(server_fd);
			}//hit, miss end
			close(client_fd);		//close client
			exit(0);			//child exit
		}//if(pid==0) end		
		close(client_fd);		//close client
	}//while(1) end
	close(proxy_fd);		//close proxy
	
	if((semctl(semid,0,IPC_RMID,arg))==-1){	//semaphore remove
		perror("semctl failed");	//error print
		exit(1);
	}

	return 0;
}
