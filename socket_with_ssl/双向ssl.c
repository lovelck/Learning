

建立socket连接之前 设置要求验证对端参数，只要是下面几个函数
SSL_CTX_set_verify, 
SSL_set_verify, 
SSL_CTX_set_verify_depth,
SSL_set_verify_depth



/*File:client.c 
 *Auth:sjin 
 *Date：2014-03-11 
 * 
 */  
#include <stdio.h> 
#include <string.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <resolv.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <sys/types.h> 
#include <sys/stat.h> 
#include <fcntl.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h>

#define MAXBUF 1024  

void ShowCerts(SSL * ssl) 
{ 
  X509 *cert; 
  char *line;    cert = SSL_get_peer_certificate(ssl); 
  if (cert != NULL) { 
    printf("Digital certificate information:\n"); 
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0); 
    printf("Certificate: %s\n", line); 
    free(line); 
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0); 
    printf("Issuer: %s\n", line); 
    free(line); 
    X509_free(cert); 
  } 
  else 
    printf("No certificate information！\n"); 
}

int main(int argc, char **argv) 
{ 
  int i,j,sockfd, len, fd, size; 
  char fileName[50],sendFN[20]; 
  struct sockaddr_in dest; 
  char buffer[MAXBUF + 1]; 
  SSL_CTX *ctx; 
  SSL *ssl;

  if (argc != 3) 
  { 
    printf("Parameter format error! Correct usage is as follows：\n\t\t%s IP Port\n\tSuch as:\t%s 127.0.0.1 80\n", argv[0], argv[0]); exit(0); 
  }

  /* SSL 库初始化 */ 
  SSL_library_init(); 
  OpenSSL_add_all_algorithms(); 
  SSL_load_error_strings(); 
  ctx = SSL_CTX_new(SSLv23_client_method()); 
  if (ctx == NULL) 
  { 
    ERR_print_errors_fp(stdout); 
    exit(1); 
  }

  /* 创建一个 socket 用于 tcp 通信 */ 
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
  { 
    perror("Socket"); 
    exit(errno); 
  } 
  printf("socket created\n");    /* 初始化服务器端（对方）的地址和端口信息 */ 
  bzero(&dest, sizeof(dest)); 
  dest.sin_family = AF_INET; 
  dest.sin_port = htons(atoi(argv[2])); 
  if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0) 
  { 
    perror(argv[1]); 
    exit(errno); 
  } 
  printf("address created\n");    /* 连接服务器 */ 
  if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) 
  { 
    perror("Connect "); 
    exit(errno); 
  } 
  printf("server connected\n\n");    /* 基于 ctx 产生一个新的 SSL */ 
  ssl = SSL_new(ctx); 
  SSL_set_fd(ssl, sockfd); 
  /* 建立 SSL 连接 */ 
  if (SSL_connect(ssl) == -1) 
    ERR_print_errors_fp(stderr); 
  else 
  { 
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl)); 
    ShowCerts(ssl); 
  }    /* 接收用户输入的文件名，并打开文件 */ 
  printf("\nPlease input the filename of you want to load :\n>"); 
  scanf("%s",fileName); 
  if((fd = open(fileName,O_RDONLY,0666))<0) 
  { 
    perror("open:"); 
    exit(1); 
  }    /* 将用户输入的文件名，去掉路径信息后，发给服务器 */ 
  for(i=0;i<=strlen(fileName);i++) 
  { 
    if(fileName[i]=='/') 
    { 
      j=0; 
      continue; 
    } 
    else {sendFN[j]=fileName[i];++j;} 
  } 
  len = SSL_write(ssl, sendFN, strlen(sendFN)); 
  if (len < 0) 
    printf("'%s'message Send failure ！Error code is %d，Error messages are '%s'\n", buffer, errno, strerror(errno));    /* 循环发送文件内容到服务器 */ 
  bzero(buffer, MAXBUF + 1);  
  while((size=read(fd,buffer,1024))) 
  { 
    if(size<0) 
    { 
      perror("read:"); 
      exit(1); 
    } 
    else 
    { 
      len = SSL_write(ssl, buffer, size); 
      if (len < 0) 
        printf("'%s'message Send failure ！Error code is %d，Error messages are '%s'\n", buffer, errno, strerror(errno)); 
    } 
    bzero(buffer, MAXBUF + 1); 
  } 
  printf("Send complete !\n");    /* 关闭连接 */ 
  close(fd); 
  SSL_shutdown(ssl); 
  SSL_free(ssl); 
  close(sockfd); 
  SSL_CTX_free(ctx); 
  return 0; 
}


/*File:server.c 
 *Auth:sjin 
 *Date：2014-03-11 
 * 
 */ 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <sys/wait.h> 
#include <unistd.h> 
#include <arpa/inet.h> 
#include <sys/types.h> 
#include <sys/stat.h> 
#include <fcntl.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h>

#define MAXBUF 1024

int main(int argc, char **argv) 
{ 
  int sockfd, new_fd, fd; 
  socklen_t len; 
  struct sockaddr_in my_addr, their_addr; 
  unsigned int myport, lisnum; 
  char buf[MAXBUF + 1]; 
  char new_fileName[50]="/newfile/"; 
  SSL_CTX *ctx; 
  mode_t mode; 
  char pwd[100]; 
  char* temp;

  /* 在根目录下创建一个newfile文件夹 */ 
  mkdir("/newfile",mode);

  if (argv[1]) 
    myport = atoi(argv[1]); 
  else 
  { 
    myport = 7838; 
    argv[2]=argv[3]=NULL; 
  }

  if (argv[2]) 
    lisnum = atoi(argv[2]); 
  else 
  { 
    lisnum = 2; 
    argv[3]=NULL; 
  }    /* SSL 库初始化 */ 
  SSL_library_init(); 
  /* 载入所有 SSL 算法 */ 
  OpenSSL_add_all_algorithms(); 
  /* 载入所有 SSL 错误消息 */ 
  SSL_load_error_strings(); 
  /* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text */ 
  ctx = SSL_CTX_new(SSLv23_server_method()); 
  /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */ 
  if (ctx == NULL) 
  { 
    ERR_print_errors_fp(stdout); 
    exit(1); 
  } 
  /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */ 
  getcwd(pwd,100); 
  if(strlen(pwd)==1) 
    pwd[0]='\0'; 
  if (SSL_CTX_use_certificate_file(ctx, temp=strcat(pwd,"/cacert.pem"), SSL_FILETYPE_PEM) <= 0) 
  { 
    ERR_print_errors_fp(stdout); 
    exit(1); 
  } 
  /* 载入用户私钥 */ 
  getcwd(pwd,100); 
  if(strlen(pwd)==1) 
    pwd[0]='\0'; 
  if (SSL_CTX_use_PrivateKey_file(ctx, temp=strcat(pwd,"/privkey.pem"), SSL_FILETYPE_PEM) <= 0) 
  { 
    ERR_print_errors_fp(stdout); 
    exit(1); 
  } 
  /* 检查用户私钥是否正确 */ 
  if (!SSL_CTX_check_private_key(ctx)) 
  { 
    ERR_print_errors_fp(stdout); 
    exit(1); 
  }    /* 开启一个 socket 监听 */ 
  if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) 
  { 
    perror("socket"); 
    exit(1); 
  } 
  else 
    printf("socket created\n");

  bzero(&my_addr, sizeof(my_addr)); 
  my_addr.sin_family = PF_INET; 
  my_addr.sin_port = htons(myport); 
  
  if (argv[3]) 
    my_addr.sin_addr.s_addr = inet_addr(argv[3]); 
  else 
    my_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1) 
  { 
    perror("bind"); 
    exit(1); 
  } 
  else 
    printf("binded\n");
  
  if (listen(sockfd, lisnum) == -1) 
  { 
    perror("listen"); 
    exit(1); 
  } 
  else 
    printf("begin listen\n");

  while (1) 
  { 
    SSL *ssl; 
    len = sizeof(struct sockaddr); 
    /* 等待客户端连上来 */ 
    if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len)) == -1) 
    { 
      perror("accept"); 
      exit(errno); 
    } 
    else 
      printf("server: got connection from %s, port %d, socket %d\n", inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port), new_fd);

    /* 基于 ctx 产生一个新的 SSL */ 
    ssl = SSL_new(ctx); 
    /* 将连接用户的 socket 加入到 SSL */ 
    SSL_set_fd(ssl, new_fd); 
    /* 建立 SSL 连接 */ 
    if (SSL_accept(ssl) == -1) 
    { 
      perror("accept"); 
      close(new_fd); 
      break; 
    }      /* 接受客户端所传文件的文件名并在特定目录创建空文件 */ 
    bzero(buf, MAXBUF + 1); 
    bzero(new_fileName+9, 42); 
    len = SSL_read(ssl, buf, MAXBUF); 
    if(len == 0) 
      printf("Receive Complete !\n"); 
    else if(len < 0) 
      printf("Failure to receive message ! Error code is %d，Error messages are '%s'\n", errno, strerror(errno)); 
    if((fd = open(strcat(new_fileName,buf),O_CREAT | O_TRUNC | O_RDWR,0666))<0) 
    { 
      perror("open:"); 
      exit(1); 
    }      /* 接收客户端的数据并写入文件 */ 
    while(1) 
    { 
      bzero(buf, MAXBUF + 1); 
      len = SSL_read(ssl, buf, MAXBUF); 
      if(len == 0) 
      { 
        printf("Receive Complete !\n"); 
        break; 
      } 
      else if(len < 0) 
      { 
        printf("Failure to receive message ! Error code is %d，Error messages are '%s'\n", errno, strerror(errno)); 
        exit(1); 
      } 
      if(write(fd,buf,len)<0) 
      { 
        perror("write:"); 
        exit(1); 
      } 
    }      /* 关闭文件 */ 
    close(fd); 
    /* 关闭 SSL 连接 */ 
    SSL_shutdown(ssl); 
    /* 释放 SSL */ 
    SSL_free(ssl); 
    /* 关闭 socket */ 
    close(new_fd); 
  }    /* 关闭监听的 socket */ 
  close(sockfd); 
  /* 释放 CTX */ 
  SSL_CTX_free(ctx); 
  return 0; 
}


Openssl双向认证客户端代码
openssl是一个功能丰富且自包含的开源安全工具箱。它提供的主要功能有：SSL协议实现(包括SSLv2、SSLv3和TLSv1)、大量软算法(对称/非对称/摘要)、大数运算、非对称算法密钥生成、ASN.1编解码库、证书请求(PKCS10)编解码、数字证书编解码、CRL编解码、OCSP协议、数字证书验证、PKCS7标准实现和PKCS12个人数字证书格式实现等功能。
本文主要介绍openssl进行客户端-服务器双向验证的通信，客户端应该如何设置。包括了如何使用openssl指令生成客户端-服务端的证书和密钥，以及使用openssl自带server端来实现简单的ssl双向认证，client端代码中也做了相应的标注和说明，提供编译的Makefile.希望对开始学习如何使用openssl进行安全连接的朋友有益。 
1． 首先介绍如何生成客户和服务端证书(PEM)及密钥。
 在linux环境下下载并安装openssl开发包后，通过openssl命令来建立一个SSL测试环境。
1） 建立自己的CA
  在openssl安装目录的misc目录下，运行脚本：./CA.sh -newca，出现提示符时，直接回车。  运行完毕后会生成一个demonCA的目录，里面包含了ca证书及其私钥。
2） 生成客户端和服务端证书申请：
  openssl  req  -newkey  rsa:1024  -out  req1.pem  -keyout  sslclientkey.pem
  openssl  req  -newkey  rsa:1024  -out  req2.pem  -keyout  sslserverkey.pem
3) 签发客户端和服务端证书
  openssl  ca  -in  req1.pem  -out  sslclientcert.pem
  openssl  ca  -in  req2.pem  -out  sslservercert.pem
4) 运行ssl服务端：
  openssl s_server -cert sslservercert.pem -key sslserverkey.pem -CAfile demoCA/cacert.pem -ssl3 
当然我们也可以使用openssl自带的客户端：
  openssl s_client -ssl3 -CAfile demoCA/cacert.pem


但这里我们为了介绍client端的设置过程，还是从一下代码来看看如何书写吧。 


#include <openssl/ssl.h> 
#include <openssl/crypto.h> 
#include <openssl/err.h> 
#include <openssl/bio.h> 
#include <openssl/pkcs12.h>
#include <unistd.h> 
#include <stdio.h> 
#include <string.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>

#define IP "172.22.14.157" 
#define PORT 4433 
#define CERT_PATH "./sslclientcert.pem" 
#define KEY_PATH  "./sslclientkey.pem" 
#define CAFILE "./demoCA/cacert.pem" 

static SSL_CTX *g_sslctx = NULL;  

int connect_to_server(int fd ,char* ip,int port)
{ 
	struct sockaddr_in svr; 
	memset(&svr,0,sizeof(svr)); 
	svr.sin_family = AF_INET; 
	svr.sin_port = htons(port); 
	if(inet_pton(AF_INET,ip,&svr.sin_addr) <= 0)
	{ 
		printf("invalid ip address!\n"); 
		return -1; 
	} 
	if(connect(fd,(struct sockaddr *)&svr,sizeof(svr)))
	{ 
		printf("connect error : %s\n",strerror(errno)); 
		return -1; 
	}  
	return 0; 
}
  
//客户端证书内容输出 
void print_client_cert(char* path) 
{ 
	X509 *cert =NULL; 
	FILE *fp = NULL; 
	fp = fopen(path,"rb"); 
	//从证书文件中读取证书到x509结构中，passwd为1111,此为生成证书时设置的 
	cert = PEM_read_X509(fp, NULL, NULL, "1111"); 
	X509_NAME *name=NULL; 
	char buf[8192]={0}; 
	BIO *bio_cert = NULL; 
	//证书持有者信息 
	name = X509_get_subject_name(cert); 
	X509_NAME_oneline(name,buf,8191); 
	printf("ClientSubjectName:%s\n",buf); 
	memset(buf,0,sizeof(buf)); 
	bio_cert = BIO_new(BIO_s_mem()); 
	PEM_write_bio_X509(bio_cert, cert); 
	//证书内容 
	BIO_read( bio_cert, buf, 8191); 
	printf("CLIENT CERT:\n%s\n",buf); 
	if(bio_cert)BIO_free(bio_cert); 
	fclose(fp); 
	if(cert) X509_free(cert); 
} 
//在SSL握手时，验证服务端证书时会被调用，res返回值为1则表示验证成功，否则为失败 
static int verify_cb(int res, X509_STORE_CTX *xs) 
{ 
	printf("SSL VERIFY RESULT :%d\n",res); 
	switch (xs->error) 
	{ 
		case X509_V_ERR_UNABLE_TO_GET_CRL: 
			printf(" NOT GET CRL!\n"); 
			return 1; 
		default : 
			break; 
	} 
	return res; 
}

int sslctx_init() 
{ 
#if 0 
	BIO *bio = NULL; 
	X509 *cert = NULL; 
	STACK_OF(X509) *ca = NULL; 
	EVP_PKEY *pkey =NULL; 
	PKCS12* p12 = NULL; 
	X509_STORE *store =NULL; 
	int error_code =0; 
#endif  	int ret =0; 
	print_client_cert(CERT_PATH); 
	//registers the libssl error strings 
	SSL_load_error_strings();  	//registers the available SSL/TLS ciphers and digests 
	SSL_library_init();  	//creates a new SSL_CTX object as framework to establish TLS/SSL 
	g_sslctx = SSL_CTX_new(SSLv23_client_method()); 
	if(g_sslctx == NULL)
	{ 
		ret = -1; 
		goto end; 
	}

  	//passwd is supplied to protect the private key,when you want to read key 
	SSL_CTX_set_default_passwd_cb_userdata(g_sslctx,"1111");  	//set cipher ,when handshake client will send the cipher list to server 
	SSL_CTX_set_cipher_list(g_sslctx,"HIGH:MEDIA:LOW:!DH"); 
	//SSL_CTX_set_cipher_list(g_sslctx,"AES128-SHA");  	//set verify ,when recive the server certificate and verify it 
	//and verify_cb function will deal the result of verification 
	SSL_CTX_set_verify(g_sslctx, SSL_VERIFY_PEER, verify_cb);  	//sets the maximum depth for the certificate chain verification that shall 
	//be allowed for ctx 
	SSL_CTX_set_verify_depth(g_sslctx, 10);  	//load the certificate for verify server certificate, CA file usually load 
	SSL_CTX_load_verify_locations(g_sslctx,CAFILE, NULL);  	//load user certificate,this cert will be send to server for server verify 
	if(SSL_CTX_use_certificate_file(g_sslctx,CERT_PATH,SSL_FILETYPE_PEM) <= 0)
	{ 
		printf("certificate file error!\n"); 
		ret = -1; 
		goto end; 
	} 
	//load user private key 
	if(SSL_CTX_use_PrivateKey_file(g_sslctx,KEY_PATH,SSL_FILETYPE_PEM) <= 0)
	{ 
		printf("privatekey file error!\n"); 
		ret = -1; 
		goto end; 
	} 
	if(!SSL_CTX_check_private_key(g_sslctx))
	{ 
		printf("Check private key failed!\n"); 
		ret = -1; 
		goto end; 
	}  
end: 
	return ret; 
}
  
void sslctx_release() 
{ 
	EVP_cleanup(); 
	if(g_sslctx){ 
		SSL_CTX_free(g_sslctx); 
	} 
	g_sslctx= NULL; 
}
 
//打印服务端证书相关内容 
void print_peer_certificate(SSL *ssl) 
{ 
	X509* cert= NULL; 
	X509_NAME *name=NULL; 
	char buf[8192]={0}; 
	BIO *bio_cert = NULL; 
	//获取server端证书 
	cert = SSL_get_peer_certificate(ssl); 
	//获取证书拥有者信息 
	name = X509_get_subject_name(cert); 
	X509_NAME_oneline(name,buf,8191); 
	printf("ServerSubjectName:%s\n",buf); 
	memset(buf,0,sizeof(buf)); 
	bio_cert = BIO_new(BIO_s_mem()); 
	PEM_write_bio_X509(bio_cert, cert); 
	BIO_read( bio_cert, buf, 8191); 
	//server证书内容 
	printf("SERVER CERT:\n%s\n",buf); 
	if(bio_cert)BIO_free(bio_cert); 
	if(cert)X509_free(cert); 
}
  
int main(int argc, char** argv)
{ 
	int fd = -1 ,ret = 0; 
	SSL *ssl = NULL; 
	char buf[1024] ={0}; 
	//初始化SSL 
	if(sslctx_init())
	{ 
		printf("sslctx init failed!\n"); 
		goto out; 
	} 
	//客户端socket建立tcp连接 
	fd = socket(AF_INET,SOCK_STREAM,0); 
	if(fd < 0)
	{ 
		printf("socket error:%s\n",strerror(errno)); 
		goto out; 
	}  
	if(connect_to_server(fd ,IP,PORT))
	{ 
		printf("can't connect to server:%s:%d\n",IP,PORT); 
		goto out; 
	} 
	ssl = SSL_new(g_sslctx); 
	if(!ssl)
	{ 
		printf("can't get ssl from ctx!\n"); 
		goto out; 
	} 
	SSL_set_fd(ssl,fd); 
	//建立与服务端SSL连接 
	ret = SSL_connect(ssl); 
	if(ret != 1)
	{ 
		int err = ERR_get_error(); 
		printf("Connect error code: %d ,string: %s\n",err,ERR_error_string(err,NULL)); 
		goto out; 
	} 
	//输入服务端证书内容 
	print_peer_certificate(ssl);  
	//SSL_write(ssl,"sslclient test!",strlen("sslclient test!")); 
	//SSL_read(ssl,buf,1024); 
	//关闭SSL连接 
	SSL_shutdown(ssl);   

out: 
	if(fd >0)
		close(fd); 
	
	if(ssl != NULL)
	{ 
		SSL_free(ssl); 
		ssl = NULL; 
	} 
	
	if(g_sslctx != NULL)
		sslctx_release(); 

	return 0; 
}



  