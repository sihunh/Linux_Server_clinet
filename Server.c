/*
   @file   Server.c
   @brief  server
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/mman.h>

//#include <winsock2.h> // windows...
//#include <Windows.h>


#define SERVER_MAX_MSG 1024

#define SERVER_MAX_WATCHFILE   100
#define SERVER_INOTIFY_SIZE   (sizeof(struct inotify_event))
#define SERVER_INOTIFY_BUFFLEN (SERVER_MAX_WATCHFILE*(SERVER_INOTIFY_SIZE+16))
// file list save buf
#define SERVER_WATCHED_BUFFLEN SHA256_DIGEST_LENGTH*SERVER_MAX_WATCHFILE 

static char serv_msg[SERVER_WATCHED_BUFFLEN] = {0x00,};
int serv_msg_len = 0;
pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t send_event = PTHREAD_COND_INITIALIZER;
static const char path_to_watch[] = "./watched_dir";

void *Server_client_handler(void *sock_desc);
int Server_make_sendmsg(const char * watch_path);
void *Server_directory_monitor(void *arg);
int Server_get_sha256(const char *file_path, unsigned char *sha256);

// Main
int main(int argc, char *argv[])
{
   int sock_desc = 0;
   int cli_sock = 0;
   int sock_opt = 1;
   int sock_len = 0;
   struct sockaddr_in serv_addr;
   struct sockaddr_in cli_addr;
   pthread_t handler_thread;

   pthread_mutex_lock(&send_lock); // thread lock
   Server_make_sendmsg(path_to_watch);
   pthread_mutex_unlock(&send_lock); // thread unlock

   if ( pthread_create (&handler_thread, NULL, Server_directory_monitor, 0) < 0)
   {
      perror("[SERVER] Fail to pthread_create()");
      return 1;
   }
   // Create socket listen
   sock_desc = socket(AF_INET, SOCK_STREAM, 0);
   if (sock_desc == -1)
   {
      perror("[SERVER] Failed to create socket");
      printf("Error code: %d\n", errno);
      return 1;
   }
   // A/S
   sock_opt = 1;
   setsockopt(sock_desc, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));
   
   if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
   {
      perror("[SERVER] Fail to signal()");
      printf("Error code: %d\n", errno);
      return 1;
   }
   // set addr
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons( 4000 );
   sock_len = sizeof(struct sockaddr_in);
   
   
   // Bind socket and address
   if(bind(sock_desc,(struct sockaddr*)&serv_addr, sizeof( serv_addr)) < 0)
   {
      perror("[SERVER] Failed to bind socket");
      printf("Error code: %d\n", errno);
      return 1;

   }
   // Listen incoming connection
   #define Server_ADDR_BACKLOG 100
   listen(sock_desc, Server_ADDR_BACKLOG);
   printf("[SERVER] 클라이언트 기다리는중 ...\n");
   
   // Accept connection form client
   while((cli_sock = accept(sock_desc, (struct sockaddr *)&cli_addr, (socklen_t*)&sock_len)))
   {
      printf("[SERVER][%d client] 연결되었음\n", cli_sock);
      // create thread to handler client
      if( pthread_create( &handler_thread, NULL, Server_client_handler, (void*)(intptr_t)cli_sock) < 0)
      {
         perror("[SERVER] Fail to create thread.");
         return 1;
      }
   }
   printf("[SERVER] exit\n");
   return 0;
}
// client handler func
void * Server_client_handler(void *sock_desc)
{
   // Get the sock
   int sock = (int)(intptr_t)sock_desc;
   int read_size = 0;
   char cli_msg[SERVER_MAX_MSG] = {0x00, };
   
   //receive a msg form cli
   read_size = recv(sock, cli_msg, SERVER_MAX_MSG-1, 0);
   if(0 < read_size)
   {
      cli_msg[SERVER_MAX_MSG-1] = 0;
      printf("[SERVER][%d client]로부터 수신 : \"%s\"\n", sock, cli_msg);
      
      do
      {
         pthread_mutex_lock(&send_lock);

         // send to cli
         if( 0 < send(sock, serv_msg, serv_msg_len, 0))
         {
            printf("[SERVER][%d client]로 송신 : \"%s\"\n", sock, serv_msg);
         }
         else
         {
            pthread_mutex_unlock(&send_lock);
            perror("[SERVER] Failed to send!");
            break;
         }
         pthread_cond_wait(&send_event, &send_lock);
         pthread_mutex_unlock(&send_lock);

      }while(1);
   }
   else if(0==read_size)
   {
      printf("[SERVER][%d client] Disconnected\n", sock);
   }
   else 
   {
      perror("[SERVER] Failed to recevie");
   }
   close(sock);
   
   printf("[SERVER][%d client] EXIT\n", sock);
   return 0;
}   
int Server_make_sendmsg(const char * watch_path)
{
   DIR *dp;
   struct dirent *ep;
   int ret = 0;
   char file_path[PATH_MAX] = {0,};
   int file_start = strlen(watch_path);
   unsigned char sha256[SHA256_DIGEST_LENGTH+1];
   
   strcpy(file_path, watch_path);
   file_path[file_start++] = '/';
   file_path[file_start] = 0;
   sha256[SHA256_DIGEST_LENGTH] = 0;

   dp = opendir(watch_path);
   if(dp != NULL)
   {
	  serv_msg_len = 0;
      serv_msg[0] = 0;
      while(NULL != (ep = readdir (dp)))
      {
         if(DT_REG == ep->d_type)
         {
            ++ret;
            if( serv_msg_len + SHA256_DIGEST_LENGTH + 2 < SERVER_WATCHED_BUFFLEN )
            {
			   file_path[file_start] = 0;
               strncat(file_path + file_start, ep->d_name, strlen(ep->d_name));
               if (0 == Server_get_sha256(file_path, sha256))
			   {
				   strncat(serv_msg + serv_msg_len, (const char*)sha256, SHA256_DIGEST_LENGTH);
				   serv_msg_len += SHA256_DIGEST_LENGTH;
			   }
            }
         }
      }
	  serv_msg[serv_msg_len] = 0;
      closedir (dp);
   } 
   else
   {
      perror ("[SERVER] Fail to opendir()");
   }
   return ret;

}
void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH],unsigned char *outputBuffer)
{
  int i = 0;
  for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    printf("%02x", hash[i]);
  }
  outputBuffer[64] = 0;
}
int Server_get_sha256(const char *file_path, unsigned char *sha256)
{
  FILE* file =fopen(file_path,"rb");
  if (!file)return -1;
   
  unsigned char hash[SHA256_DIGEST_LENGTH];
  const int bufSize = 32768;
  unsigned char *buffer = (unsigned char *)malloc(bufSize);
  SHA256_CTX sh1a256;
  int bytesRead = 0;
 
  if (!buffer)return -2;
  if(file < 0)
  {
	  printf("file : %s\n",file_path);
	  perror("[SERVER] Failed to open");
	  return -1;
  }
  memset(sha256,0,SHA256_DIGEST_LENGTH);
 
  SHA256_Init(&sh1a256);
 
  while ((bytesRead =fread(buffer, 1, bufSize, file))) {
    SHA256_Update(&sh1a256, buffer, bytesRead);
  }
 
  SHA256_Final(hash, &sh1a256);
  printf("[SERVER] file: %s sha256 : \n", file_path);
  sha256_hash_string(hash, sha256);
  fclose(file);
 
  return 0;

}
void *Server_directory_monitor(void *arg)
{
   int read_len = 0;
   int event_index = 0;
   int dir_changed = 0;
   int fd, wd = 0;
   char buffer[SERVER_INOTIFY_BUFFLEN];
   struct inotify_event *event = NULL;

   printf("[SERVER] 모니터링을 시작합니다. \n");

   fd = inotify_init();
   if (fd < 0)
   {
      perror("[SERVER] Failed to inotify_init()");
   }
   wd = inotify_add_watch(fd, path_to_watch, IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO);
   do
   {
      event_index = 0;
      dir_changed = 0;

      read_len = read(fd, buffer, SERVER_INOTIFY_BUFFLEN);
      if(read_len < 0)
      {
         perror("[SERVER] Failed to read()");
      }
      while(event_index < read_len)
      {
         event = (struct inotify_event *) &buffer[event_index];
         if(event->len)
         {
            if(event->mask & IN_CREATE)               
            {
               printf("[SERVER] %s 파일이 생성이 감지되었습니다. \n", event->name);
               dir_changed = 1;
            }
            else if(event->mask & IN_DELETE)               
            {
               printf("[SERVER] %s 파일이 삭제가 감지되었습니다. \n", event->name);
               dir_changed = 1;
            }
            else if(event->mask & IN_MOVED_FROM || event->mask & IN_MOVED_TO)               
            {
               printf("[SERVER] %s 파일이 이동이 감지되었습니다. \n", event->name);
               dir_changed = 1;
            }
            event_index += SERVER_INOTIFY_SIZE + event->len;
         }
         else
         {
            event_index += SERVER_INOTIFY_SIZE;
         }
      }
      if (1 == dir_changed)
      {
         pthread_mutex_lock(&send_lock);
         Server_make_sendmsg(path_to_watch);
         pthread_cond_broadcast(&send_event);
         pthread_mutex_unlock(&send_lock);
      }
   }while(1);

   inotify_rm_watch(fd , wd);
   close( fd );
   printf("[SERVER] 모니터링 종료\n");

   return 0;

}