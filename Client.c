/** 
 * @ file	Client.c
 * @ brief 	prototype
*/
#include <linux/init.h>	// for init, exit macro
#include <linux/module.h> // core header for lkm
#include <linux/kernel.h> // core header for kernel
#include <linux/binfmts.h> // for bprm
#include <asm-generic/errno-base.h>

//////////////////////////////// socket

#include <linux/net.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <linux/kthread.h>
#include <linux/version.h>

#include <linux/crypto.h> // hash_desc
#include <crypto/sha.h> // sha256 


/////////////////////////////////////////////////////

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TEST");
MODULE_DESCRIPION("PROTOTPYE");
MODULE_VERSION("0.1"); 

/////////////////////////////////////////////////////

#define Client_MAX_MSG 512

// thread for sock client
static struct task_struct * Client_sock_thread = 0; 
// sock
struct socket * sock = NULL; 


// Module Init function	
static int __init Client_init(void);
// Module Exit function
static void __exit Client_exit(void); 

// Set init function to kernel
module_init(Client_init);
// Set exit function to kernel
module_exit(Client_exit);

// symbols from kernel
typedef int (*security_bprm_check_func)(struct linux_binprm *bprm);
extern void security_bprm_check_set_process_filter( security_bprm_check_func pfunc); // linux 커널 내 security.c 파일에 추가 내용
extern void security_bprm_check_unset_process_filter(void); // linux 커널 내 security.c 파일에 추가 내용
// filter function 
static int Process_filter_func(struct linux_binprm *bprm);

//send socket wrapper
ssize_t Client_send(struct socket *sk, const void *buffer, size_t length, int flags);
//recieve socket wrapper
ssize_t Client_recv(struct socket *sk, void *buffer, size_t length, int flags);
//socket close
void Client_close(struct socket *sk);
//client socket thread func
static int Client_client_func(void *arg);
//shut down socket
int Client_shutdown(struct socket *sk, int h);
// print buffer hex
void Client_print_hex(const unsigned char * buf, int size);
// Get sha256
int Client_get_sha256(struct file* file, unsigned char *sha256);
  

///////////////////////////////////////////////////////////////////////////////

// Module Init function	
static int __init Client_init(void){
	printk(KERN_INFO "[Client] Start Filtering\n" );
	// set filter 	
	security_bprm_check_set_process_filter(process_filter_func);

	// start thread for client
	Client_sock_thread = kthread_create(Client_client_func, NULL, "Client_process_filter");
	if(NULL != Client_sock_thread)
		wake_up_process(Client_sock_thread);

	return 0;
}

 
// Module Exit function
static void __exit Client_exit(void){
	// shutdown rec socket to terminate thread
	Client_shutdown(sock,SHUT_RDWR);

	// stop thread 
	if( 0 != Client_sock_thread)
	{
		kthread_stop(Client_sock_thread);
		Client_sock_thread = 0;
	}

	// unset filter before exit
	security_bprm_check_unset_process_filter();
	printk(KERN_INFO "[Client] Terminate\n" );
}


// filter function 
static int process_filter_func(struct linux_binprm *bprm)
{
   unsigned char sha256[SHA256_DIGEST_SIZE];
   
   memset(sha256, 0 ,SHA256_DIGEST_SIZE);

   if(0 == Client_get_sha256(bprm->file, sha256))
   {
      printk(KERN_INFO "[Client] file : %s, sha256 : ", bprm->filename);
      Client_print_hex(sha256, SHA256_DIGEST_SIZE);
   }

	printk(KERN_INFO "[Client] New process (file:%s)\n", bprm->filename);

	if( NULL != bprm->filename && NULL != strstr(bprm->filename, "virus") ) // 수정해야함 
	{
		printk(KERN_INFO "[Client] file blocked!(file:%s)\n", bprm->filename);
		return -EACCES;
	}
	return 0;
} 
// socket send wrapper
ssize_t Client_send(struct socket * sk, const void *buffer, size_t length, int flags)
{
	struct msghdr msg;
	struct iovec iov;
	int ret = 0;

	//msg
	iov.iov_base = (void *)buffer;
	iov.iov_len = (__kernel_size_t)length;

	#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,0,0) 
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
	#else
		iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, length);
	#endif
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = flags;
	#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,0,0)
		// send message
		ret = sock_sendmsg(sk, &msg, length);
	#else
		// send message
		ret = sock_sendmsg(sk, &msg);
	#endif
	
	return ret;
}
	// recv socket wrapper
ssize_t Client_recv(struct socket * sk, void *buffer, size_t length, int flags)
{
	struct msghdr msg;
	struct iovec iov;
	int ret;
	
	// Set message
	iov.iov_base = (void *)buffer;
	iov.iov_len = (__kernel_size_t)length;

	#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,0,0)
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
	#else
		iov_iter_init(&msg.msg_iter, READ, &iov, 1, length);
	#endif
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = flags;
	
	// Receive message
	ret =  sock_recvmsg(sk, &msg, flags);

	return ret;
}
// shutdown
int Client_shutdown(struct socket *sk, int h)
{
	int ret = 0;
	
	if (sk)
		ret = sk->ops->shutdown(sk, h);
	return ret;

}

void Client_close(struct socket *sk)
{
	sk->ops->release(sk);
	if(sk)
		sock_release(sk);
}
static int Client_client_func(void *arg)
{
	struct sockaddr_in serv_addr;
	static const char * cli_msg = "This is Client";
	char serv_msg[Client_MAX_MSG] = {0x00, };
	int ret = -1;
	
	// socket create
	ret = sock_create(AF_INET, SOCK_STREAM, 0, &sock);
	if(ret != -1)
	{
		serv_addr.sin_addr.s_addr = in_aton("192.168.110.132");
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(4000);
		
		do
		{
			ret = sock->ops->connect(sock , (struct sockaddr *)&serv_addr , sizeof(serv_addr), 0);
			if (0 <= ret)
			{
				ret = Client_send(sock, cli_msg, strlen(cli_msg), 0);
				if (0 >= ret)
				{
					printk(KERN_ERR "[Client] Send fail");
					break; 
				}
				printk("[Client] Sent : \"%s\"\n", cli_msg);
			
				while(1)
				{
					// recieve
					ret = Client_recv(sock, serv_msg, Client_MAX_MSG-1, 0);
					if(0 >= ret)
					{
						printk(KERN_ERR " [Client] Failed to receive\n");
						break;
					}
					serv_msg[ret] = 0;	

					printk("[Client] Received : \"%s\"\n", serv_msg);
				}
			}
			else
			{
				printk(KERN_ERR "[Client] Failed to connect");
				break;
			}	
		}while(0);
		if(NULL != sock)
		{
			Client_close(sock);
			sock = NULL;
		}	
	}
	else
	{
		printk(KERN_ERR "[Client] Could not create socket");
	}
	
	Client_sock_thread = NULL;

	return ret;
}
void Client_print_hex(const unsigned char * buf, int size)
{
   int i=0;

   for(i=0; i < size; i++)
   {
      printk(KERN_CONT "%02x",buf[i]);
   }
}
int Client_get_sha256(struct file* file, unsigned char *sha256)
{
    int ret = 0;
    int success = 0;
    struct crypto_shash *handle = NULL;
    struct shash_desc* shash = NULL;
    unsigned char *buff = NULL; // 파일 버퍼
    size_t buff_size = 16 * 1024; // page_size   
    loff_t file_size = 0; 
    int retval = 0; 
       
    handle = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(handle))
    {
        // 핸들 얻기 실패
	printk(KERN_ERR "[Client] Fail to get handle");
        goto EXIT_ERROR;
    }
    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(handle), GFP_KERNEL);
    if (NULL == shash)
    {
        // 메모리 할당 실패
	printk(KERN_ERR "[Client] Fail to kmalloc()");
        goto EXIT_ERROR;
    }
     
    shash->tfm = handle;
     
    buff = kmalloc(buff_size, GFP_KERNEL);
    if (NULL == buff)
    {
        // 메모리 할당 실패
	printk(KERN_ERR "[Client] Fail to kmalloc()");
        goto EXIT_ERROR;
    }
     
    success = crypto_shash_init(shash);
    if (success < 0)
    {
	printk(KERN_ERR "[Client] Fail to crypto_shash_init()");
        goto EXIT_ERROR;
    }   
    while (1)
    {
        // 페이지 단위로 읽어들임
        retval = kernel_read(file,(char*)buff, buff_size, &file_size);

        if (0 > retval) goto EXIT_ERROR;
        if (0 == retval) break;

        file_size += retval;
        success = crypto_shash_update(shash, buff, retval);
        if (success < 0)  goto EXIT_ERROR;      
    }
    success = crypto_shash_final(shash, sha256);

    if (success < 0) goto EXIT_ERROR;

    goto EXIT; 
     
EXIT_ERROR:
    ret = -1;
EXIT:   
    if (buff) kfree(buff);
    if (shash) kfree(shash);     
    if (handle) crypto_free_shash(handle);
    return ret; 
}