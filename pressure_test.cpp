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
#include <map>
#include <vector>
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
#include <rapidjson/document.h> 
#include <rapidjson/prettywriter.h>
#include <rapidjson/rapidjson.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include "SHA1.h"
#include "boost/uuid/uuid.hpp" 
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"


int s_pkgNum=0;

using namespace std;
using namespace boost::uuids;

struct stEndPoint
{
    char *ip;
    unsigned short int port;
};

std::string strSessionId = "";

int s_iFunc = 0;
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

std::string GenLMUUID()
{
    uint32_t uiNow = time(NULL);
    uint32_t uiRandTime = uiNow;
    uint32_t uiRand_one = random();
    uint32_t uiRand_two = random();
    uint32_t uiRand_three = random();
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    if (!uuid.is_nil()) {
        //如果有UUID，则取UUID字节位
        unsigned char * cPtr = &(uuid.data[0]);
        memcpy(&uiRandTime, cPtr, 4);
        cPtr = cPtr + 4;
        memcpy(&uiRand_one, cPtr, 4);
        cPtr = cPtr + 4;
        memcpy(&uiRand_two, cPtr, 4);
        cPtr = cPtr + 4;
        memcpy(&uiRand_three, cPtr, 4);
    }

    char szShareIdArray[34] = { 0 };
    snprintf(szShareIdArray, sizeof(szShareIdArray), "%08X%08X%08X%08X", uiRandTime, uiRand_one, uiRand_two, uiRand_three);

    return string(szShareIdArray);
}
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

    template<class T>
std::string ToStr(T value)
{
    stringstream oSS;
    oSS << value ;
    return oSS.str();
}
std::string char2hex( char dec )
{
    char dig1 = (dec&0xF0)>>4;
    char dig2 = (dec&0x0F);
    if ( 0<= dig1 && dig1<= 9) dig1+=48;    //0,48 in ascii
    if (10<= dig1 && dig1<=15) dig1+=97-10; //A,65 in ascii
    if ( 0<= dig2 && dig2<= 9) dig2+=48;
    if (10<= dig2 && dig2<=15) dig2+=97-10;

    std::string r;
    r.append( &dig1, 1);
    r.append( &dig2, 1);
    return r;
}
std::string SHA1(const string& strSource)
{
    CSHA1 sha1;
    sha1.Update((unsigned char*)strSource.data(),strSource.size());
    sha1.Final();
    string digst;
    digst.resize(20);
    sha1.GetHash((unsigned char *)digst.data());
    string strRet;
    for(unsigned int i=0; i<digst.size();i++)
    {
        strRet+= char2hex(digst[i]);
    }
    return strRet;
}
string GetCode(std::map<string,string>& mapParams)
{
    if(mapParams.empty())
    {
        return "";
    }
    //add appsecret
    std::vector<std::string> vecKeys;
    for(std::map<string,string>::iterator iter = mapParams.begin();
            iter != mapParams.end();iter++)
    {
        vecKeys.push_back(iter->first);
    }

    //sort
    sort(vecKeys.begin(), vecKeys.end());
    string strSorted;

    for(std::vector<string>::iterator iter = vecKeys.begin();
            iter != vecKeys.end();iter++)
    {
        std::map<string,string>::iterator iterValue = mapParams.find(*iter);
        if(iterValue != mapParams.end())
        {
            string strValue = iterValue->second;
            strSorted += (*iter) + "=" + strValue + "&";
        }

    }
    strSorted = strSorted.substr(0,strSorted.length()-1);
    std::cout << "strSorted:" << strSorted << endl;
    string strCalCode = SHA1(strSorted);

    return strCalCode; 
}

void GetParamsByFunction(int iFunc,string& strJsonParams,string& strFuncName)
{
    //http://test.out.wechat.com/luck_money/lmlogic.LMLogicSvr.DirectSendLM
    //http://test.out.wechat.com/luck_money/lmlogic.LMLogicSvr.CreateLM
    //http://test.out.wechat.com/luck_money/lmlogic.LMLogicSvr.GetLM
    //http://test.out.wechat.com/luck_money/lmlogic.LMLogicSvr.ModifyLM
    //http://test.out.wechat.com/luck_money/lmlogic.LMLogicSvr.QueryUser

    string strAppId 	= "wxcbedf3b4ee3b6458";
    string strAppSec 	= "db2f3409b971199cff40f29a1e4fa073";
    uint32_t uiTimeStamp = (uint32_t)time(NULL);
    string strOpenId = "otnzBjhWHQm-kqVisJgaO2LdgUCc";


    std::cout << "test functions :" << endl;
    std::cout << "1.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.AddFav" << endl;
    std::cout << "2.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.QueryFavList" << endl;
    std::cout << "3.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.UpdateFav" << endl;
    std::cout << "4.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.DelFav" << endl;
    std::cout << "5.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.QueryFavDetail" << endl;
    std::cout << "6.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.QueryOrderList" << endl;
    std::cout << "7.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.QueryOrderDetail" << endl;
    std::cout << "8.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.GetOrderPackage" << endl;
    std::cout << "9.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.QueryUserConfig" << endl;
    std::cout << "10.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.SetUserConfig" << endl;
    std::cout << "11.http://test.out.wechat.com/billpayment/bplogic.BillPaymentService.DelOrder" << endl;
    std::cout << "now testing : " << iFunc << endl;

    if(iFunc > 11)
    {
        return;
    }


    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType& allocator = doc.GetAllocator();

    std::map<string,string> mapParams;
    switch(iFunc)
    {
        case 1:
            {
                strFuncName = "bplogic.BillPaymentService.AddFav";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 
                rapidjson::Value data(rapidjson::kObjectType);

                data.AddMember("contact_name","kris",allocator); 
                data.AddMember("contact_number","18665324573",allocator); 
                data.AddMember("product_name","tmu",allocator); 
                data.AddMember("account_number","djskdjsk-0909",allocator); 
                data.AddMember("bill_nickname","sssgggsg",allocator);
                doc.AddMember("data",data,allocator);
                break;
            }
        case 2:
            {
                strFuncName = "bplogic.BillPaymentService.QueryFavList";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 
                rapidjson::Value data(rapidjson::kObjectType);

                doc.AddMember("page",1,allocator);
                doc.AddMember("pagesize",5,allocator);
                break;
            }
        case 3:
            {
                strFuncName = "bplogic.BillPaymentService.UpdateFav";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 
                rapidjson::Value data(rapidjson::kObjectType);

                data.AddMember("id",10043,allocator);
                data.AddMember("contact_name","kris",allocator); 
                data.AddMember("contact_number","18665324573",allocator); 
                data.AddMember("product_name","tmu",allocator); 
                data.AddMember("account_number","djskdjsk-0909",allocator); 
                data.AddMember("bill_nickname","sssgggsg",allocator);
                doc.AddMember("data",data,allocator);

                break;
            }
        case 4:
            {
                strFuncName = "bplogic.BillPaymentService.DelFav";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 
                rapidjson::Value data(rapidjson::kObjectType);

                doc.AddMember("id",10043,allocator);

                break;
            }
        case 5:
            {
                strFuncName = "bplogic.BillPaymentService.QueryFavDetail";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 
                rapidjson::Value data(rapidjson::kObjectType);

                doc.AddMember("favid",10030,allocator);

                break;
            }
        case 6:
            {
                strFuncName = "bplogic.BillPaymentService.QueryOrderList";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 
                rapidjson::Value data(rapidjson::kObjectType);

                doc.AddMember("page",1,allocator);
                doc.AddMember("pagesize",5,allocator);
                break;
            }
        case 7:
            {
                strFuncName = "bplogic.BillPaymentService.QueryOrderDetail";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 
                rapidjson::Value data(rapidjson::kObjectType);

                doc.AddMember("transid","201511AHJHJAHSJAHJSASJAHJSHAJ",allocator);
                break;
            }
        case 8:
            {
                strFuncName = "bplogic.BillPaymentService.GetOrderPackage";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 
                doc.AddMember("tofav",1,allocator);
                rapidjson::Value data(rapidjson::kObjectType);

                data.AddMember("currency_code","HKD",allocator);
                data.AddMember("contact_name","runrunbian",allocator); 
                data.AddMember("contact_number","18665324573",allocator); 
                data.AddMember("product_name","tmu",allocator); 
                data.AddMember("account_number","djskdjsk-0909",allocator); 
                data.AddMember("amount",123,allocator);
                data.AddMember("tax",123,allocator);
                doc.AddMember("data",data,allocator);

                break;
            }
        case 9:
            {
                strFuncName = "bplogic.BillPaymentService.QueryUserConfig";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 

                break;
            }
        case 10:
            {
                strFuncName = "bplogic.BillPaymentService.SetUserConfig";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 

                doc.AddMember("data","201511AHJHJAHSJAHJSASJAHJSHAJ",allocator);
                break;
            }
        case 11:
            {
                strFuncName = "bplogic.BillPaymentService.DelOrder";
                //gen json
                rapidjson::Value sessionID(rapidjson::kStringType);
                sessionID.SetString(strSessionId.c_str(),strSessionId.size());
                doc.AddMember("sessionid",sessionID,allocator); 

                doc.AddMember("transid","201511008D53B9074A5F160EB3E39821B0DBE6",allocator);
                break;
            }

        default:
            break;

    }
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);
    strJsonParams = buffer.GetString();
    //int iContentLen = strJson.length();
    std::cout << "strJsonParams:" << strJsonParams << endl;
    return ;
}



static void *readwrite_routine( void *arg )
{

    co_enable_hook_sys();

    stEndPoint *endpoint = (stEndPoint *)arg;
    std::ostringstream sBuf;

    //
    string strFuncName ;
    string strJsonParams ;
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
            tv.tv_sec=5;
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
        //int iContentLen = strJson.length();
        sBuf<<"GET /" << "cgi-bin/CGINotify_json?alarmid=453&content=%7b%22Content%22%3a%22WeChat-%3e%e7%94%a8%e6%88%b7%e4%bd%93%e9%aa%8c+%5b%e4%b8%a5%e9%87%8d%5d%5c%5cn%5c%5cnTime%3a14%3a35+%5cn+AlarmIP%3a10.192.100.25%5c%5cnContent%3aibgRouter+ERROR+level+errorcode+10006+occurs+9+times%2c+more+than+threshold+5%5c%5cnError+description%3a+Forward+Failed%5cn(alarm_key%3ashell_2803)%5cn%5cn%e8%b4%9f%e8%b4%a3%e4%ba%ba%3akriswu%22%2c%22Title%22%3a%22WeChat-%3e%e7%94%a8%e6%88%b7%e4%bd%93%e9%aa%8c+%5b%e4%b8%a5%e9%87%8d%5d%22%2c%22uworkContent%22%3a%22an+alarm+happend%2calarmkey%3ashell_2803+%402016-08-22+14%3a35%3a02%22%2c%22ResponsiblePerson%22%3a%22kriswu%22%2c%22AlarmWay%22%3a%22rtx%22%2c%22Receivers%22%3a%22kriswu%22%2c%22Uworkids%22%3a%22%22%7d" <<" HTTP/1.1\r\nUser-Agent: curl/7.15.1.(x86_64-suse-linux).libcurl/7.15.1.OpenSSL/0.9.8a.zlib/1.2.3.libidn/0.6.0 Language/zh_CN\r\nHost: 10.6.222.154:80\r\nAccept: */*\r\n\r\n";


        string Request=sBuf.str();

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
                printf("%s\n",buf);
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
    if(argc < 6)
    {
        std::cout << "USAGE:"<< endl;
        std::cout << argv[0] << "cnt proccnt pkgnum "<< endl;
    	return 0;
	}
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
