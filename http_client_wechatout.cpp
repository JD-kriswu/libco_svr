/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#include "co_routine.h"

#include <errno.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <stack>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <fstream>
#include <sstream>
#include <iostream>

int s_pkgNum=0;

using namespace std;
struct stEndPoint
{
	char *ip;
	unsigned short int port;
};

static void SetAddr(const char *pszIP,const unsigned short shPort,struct sockaddr_in &addr)
{
	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(shPort);
	int nIP = 0;
	if( !pszIP || '\0' == *pszIP   
			|| 0 == strcmp(pszIP,"0") || 0 == strcmp(pszIP,"0.0.0.0") 
			|| 0 == strcmp(pszIP,"*") 
	  )
	{
		nIP = htonl(INADDR_ANY);
	}
	else
	{
		nIP = inet_addr(pszIP);
	}
	addr.sin_addr.s_addr = nIP;

}

static int iSuccCnt = 0;
static int iFailCnt = 0;
static int iTime = 0;

void AddSuccCnt()
{
	int now = time(NULL);
	if (now >iTime)
	{
		printf("time %d Succ Cnt %d Fail Cnt %d\n", iTime, iSuccCnt, iFailCnt);
		iTime = now;
		iSuccCnt = 0;
		iFailCnt = 0;
	}
	else
	{
		iSuccCnt++;
	}
}
void AddFailCnt()
{
	int now = time(NULL);
	if (now >iTime)
	{
		printf("time %d Succ Cnt %d Fail Cnt %d\n", iTime, iSuccCnt, iFailCnt);
		iTime = now;
		iSuccCnt = 0;
		iFailCnt = 0;
	}
	else
	{
		iFailCnt++;
	}
}




static void *readwrite_routine( void *arg )
{

	co_enable_hook_sys();

	stEndPoint *endpoint = (stEndPoint *)arg;
       std::ostringstream sBuf;

    string body="{\"countryID\":\"CN\",\"openid\":\"oP8B4uIqHENl7O7Y7CHlIY5MrB70\",\"platform\":\"ANDROID\",\"openkey\":\"hardcode\"}";

	sBuf<<"POST /tencent.ibg.wechatout.WeChatOutSrv.GetUserBalance HTTP/1.1\r\nUser-Agent: curl/7.15.1.(x86_64-suse-linux).libcurl/7.15.1.OpenSSL/0.9.8a.zlib/1.2.3.libidn/0.6.0\r\nHost: 10.197.7.228:45004\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: "<<body.size()<<"\r\n\r\n"<<body;

    string Request=sBuf.str();


	char buf[ 1024 * 16 ];
	int fd = -1;
	int ret = 0;
    int loopcnt=s_pkgNum;
	while(loopcnt>0)
	{
        loopcnt--;
		if ( fd < 0 )
		{
			fd = socket(PF_INET, SOCK_STREAM, 0);
            struct timeval tv;
            tv.tv_sec=2;
            tv.tv_usec=0;
            setsockopt( fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
			struct sockaddr_in addr;
			SetAddr(endpoint->ip, endpoint->port, addr);
			ret = connect(fd,(struct sockaddr*)&addr,sizeof(addr));
						
			if ( errno == EALREADY || errno == EINPROGRESS )
			{       
				struct pollfd pf = { 0 };
				pf.fd = fd;
				pf.events = (POLLOUT|POLLERR|POLLHUP);
				co_poll( co_get_epoll_ct(),&pf,1,200);
				//check connect
				int error = 0;
				uint32_t socklen = sizeof(error);
				errno = 0;
				ret = getsockopt(fd, SOL_SOCKET, SO_ERROR,(void *)&error,  &socklen);
				if ( ret == -1 ) 
				{       
					//printf("getsockopt ERROR ret %d %d:%s\n", ret, errno, strerror(errno));
					close(fd);
					fd = -1;
					AddFailCnt();
					continue;
				}       
				if ( error ) 
				{       
					errno = error;
					//printf("connect ERROR ret %d %d:%s\n", error, errno, strerror(errno));
					close(fd);
					fd = -1;
					AddFailCnt();
					continue;
				}       
			} 
	  			
		}
		


        //send loop
        ret=0;
        int iHaveSend=0;
        char *pData=(char *)Request.data();

        while(iHaveSend<Request.size())
        {
            ret = write( fd,pData+iHaveSend, Request.size()-iHaveSend);
            if(ret<=0)
            {
				close(fd);
				fd = -1;
				AddFailCnt();
                printf("write failed\n");
                break;
            }
            iHaveSend+=ret;
        }
        
        if(fd<0) continue;

        
    
        //read loop
        int iHaveRead=0;
        while(1)
		{
			ret = read( fd,buf+iHaveRead, sizeof(buf)-iHaveRead );

			if ( ret <= 0 )
			{
                if(EINPROGRESS==errno) continue;
				close(fd);
				fd = -1;
                buf[iHaveRead]=0;
                printf("read failed,ret=%d,iHaveRead;%d,errno:%d,%s,buf:%s\n",ret,errno,iHaveRead,strerror(errno),buf);
				AddFailCnt();
                break;
			}
            iHaveRead+=ret;
            char *p=strstr(buf,"\r\n\r\n");
            if(p==NULL) continue;            
            int iHeadSize=p+4-buf;
            
            char *q=strcasestr(buf,"Content-length:");
            if(q==NULL) 
            {
    
				close(fd);
				fd = -1;
				AddFailCnt();
                break;
            }
            q += 15;
            int contentlen = atoll(q);
            
            if((iHeadSize+contentlen)<=iHaveRead)
            {
				AddSuccCnt();

                buf[iHaveRead]=0;
                //printf("%s\n",buf);
			//	close(fd);
			//	fd = -1;
                break;
            }

		}
	}
    if(fd>0) close(fd);
	return 0;
}

int main(int argc,char *argv[])
{
	stEndPoint endpoint;
	endpoint.ip = argv[1];
	endpoint.port = atoi(argv[2]);
	int cnt = atoi( argv[3] );
	int proccnt = atoi( argv[4] );
	s_pkgNum= atoi( argv[5] );
	
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sigaction( SIGPIPE, &sa, NULL );
	
	for(int k=0;k<proccnt;k++)
	{

		pid_t pid = fork();
		if( pid > 0 )
		{
			continue;
		}
		else if( pid < 0 )
		{
			break;
		}
		for(int i=0;i<cnt;i++)
		{
			stCoRoutine_t *co = 0;
			co_create( &co,NULL,readwrite_routine, &endpoint);
			co_resume( co );
		}
		co_eventloop( co_get_epoll_ct(),0,0 );

		exit(0);
	}
	return 0;
}
/*./example_echosvr 127.0.0.1 10000 100 50*/
