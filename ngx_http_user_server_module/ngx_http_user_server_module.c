#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sqlite3.h>
// static void *ngx_http_location_count_create_main_conf(ngx_conf_t *cf);
// static void *ngx_http_location_count_create_server_conf(ngx_conf_t *cf);
static void *ngx_http_location_count_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_location_count_create_cmd_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_location_count_shm_zone_init(ngx_shm_zone_t *zone, void *data);
static ngx_int_t ngx_http_user_server_handler(ngx_http_request_t *r);
static void ngx_http_pagecount_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

typedef struct {
	
	ngx_rbtree_t rbtree;
	ngx_rbtree_node_t sentinel;

} ngx_http_location_count_shm_t;

typedef struct {

	ssize_t shmsize;
	ngx_slab_pool_t *pool;

	ngx_http_location_count_shm_t *lcshm;

	//ngx_uint_t interval;
	//ngx_uint_t client_count;

} ngx_http_location_conf_t;

static ngx_command_t ngx_http_location_count_cmd[] = {

	{
		ngx_string("user_server"),
		NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
		ngx_http_location_count_create_cmd_set,		
		NGX_HTTP_LOC_CONF_OFFSET,
		0, NULL	
	},
	ngx_null_command
};

static ngx_http_request_t* gr = NULL;
static ngx_log_t *gglogss = NULL;
// static void http_log(char *src) {
// 	//if (gglogss)
// 	// ngx_log_error(NGX_LOG_EMERG, gglogss, 0, "sadcsdcsdcsdc");

// 	ngx_log_error(NGX_LOG_EMERG, gr->connection->log, ngx_errno, src);
// 	// FILE *fp = fopen("log.log", "ab+");
//     // fwrite(src, strlen(src), 1, fp);
//     // fflush(fp);
//     // fclose(fp);
// }

static ngx_http_module_t ngx_http_location_count_ctx = {

	NULL,	//preconfiguration
	NULL,	//postconfiguration

	NULL,	//ngx_http_location_count_create_main_conf,	//create_main_conf
	NULL,	//init_main_conf

	NULL,	//ngx_http_location_count_create_server_conf,	//create_srv_conf
	NULL,	//merge_srv_conf

	ngx_http_location_count_create_loc_conf,	//create_loc_conf
	NULL,	//merge_loc_conf
};

ngx_module_t ngx_http_user_server_module = {

	NGX_MODULE_V1,
	&ngx_http_location_count_ctx,
	ngx_http_location_count_cmd,
	NGX_HTTP_MODULE,
	
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,

	NGX_MODULE_V1_PADDING,
};

static void *ngx_http_location_count_create_loc_conf(ngx_conf_t *cf){

	ngx_http_location_conf_t *conf = ngx_palloc(cf->pool, sizeof(ngx_http_location_conf_t));
	if(conf == NULL) {
		return NULL;
	}
	gglogss = cf->log;
	//ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "ng1111111111111111x_http_location_count_create_loc_conf %d", ngx_errno);
		
	return conf;
	
}  

static char *ngx_http_location_count_create_cmd_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	// return NULL;
	ngx_http_location_conf_t *lconf = (ngx_http_location_conf_t*)conf;
	ngx_str_t name = ngx_string("location_count_slab");

	lconf->shmsize = 128*1024;

	//申请一块共享内存，存入模块数据
	//业务：统计客户端访问次数
	//因为客户端每次访问资源的时候可能在nginx的不同work进程中，因此把访问次数存放在共享内存中方便任意进程访问
	ngx_shm_zone_t *zone = ngx_shared_memory_add(cf, &name, lconf->shmsize, &ngx_http_user_server_module);
	if(zone == NULL){
		return NGX_CONF_ERROR;
	}

	//共享内存初始化时调用的回调函数
	zone->init = ngx_http_location_count_shm_zone_init;
	zone->data = lconf;

	ngx_http_core_loc_conf_t *corecf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	//每次请求的回调函数
	corecf->handler = ngx_http_user_server_handler;

	ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "ngx_http_location_count_create_cmd_set");
	
	return NULL;
	
}

static ngx_int_t ngx_http_location_count_shm_zone_init(ngx_shm_zone_t *zone, void *data){

	ngx_http_location_conf_t *conf;
	ngx_http_location_conf_t *oconf = data;

	conf = (ngx_http_location_conf_t*)zone->data;
	if (oconf) {
		conf->lcshm = oconf->lcshm;
		conf->pool = oconf->pool;
		return NGX_OK;
	}

	printf("ngx_http_location_count_shm_zone_init 0000\n");
	
	conf->pool = (ngx_slab_pool_t*)zone->shm.addr;
	conf->lcshm = ngx_slab_alloc(conf->pool, sizeof(ngx_http_location_conf_t));
	if (conf->lcshm == NULL) {
		return NGX_ERROR;
	}

	conf->pool->data = conf->lcshm;

	printf("ngx_http_location_count_shm_zone_init 1111\n");

	//rbtree init
	//创建红黑树，存放客户端的访问次数，该红黑树在共享内存中
	ngx_rbtree_init(&conf->lcshm->rbtree, &conf->lcshm->sentinel, 
		ngx_http_pagecount_rbtree_insert_value);	

	return NGX_OK;

}

static ngx_int_t ngx_http_location_count_rbtree_lookup(ngx_http_request_t *r, ngx_http_location_conf_t *conf, ngx_uint_t key){

	ngx_rbtree_node_t *node, *sentinel;

	node = conf->lcshm->rbtree.root; 
	sentinel = conf->lcshm->rbtree.sentinel;

	//search node
	while(node != sentinel){

		if(key < node->key) {
			node = node->left;
			continue;
		} else if (key > node->key) {
			node = node->right;
			continue;
		} else {
			node->data ++;	
			return NGX_OK;
		}
	}
	
	//if not exit then insert in rbtree

	//在共享内存中分配内存
	node = ngx_slab_alloc_locked(conf->pool, sizeof(ngx_rbtree_node_t));
	if(node == NULL){
		return NGX_ERROR;
	}
	node->key = key;
	node->data = 1;

	ngx_rbtree_insert(&conf->lcshm->rbtree, node);

	ngx_log_error(NGX_LOG_EMERG, r->connection->log, ngx_errno, " insert success\n");
	
	return NGX_OK;
}

static int ngx_encode_http_page_rb(ngx_http_location_conf_t *conf, char *html, int err_code, int duration){
//	err_code = 0;
//	duration = 14;
	sprintf(html, "{\"code\": %d, \"data\": {\"access_token\": \"A8A44C5E59D19816F341F790F2D53C58\", \"vip_else\": %d, \"userid\": 4029, \"time\": 1714753694}, \"sign\":\"DA361986676E8A4864370A2C882DF79A\", \"msg\": \"login success1\"}",
	err_code, duration);
//	strcat(html, "<h2>");
	
	//ngx_rbtree_traversal(&ngx_pv_tree, ngx_pv_tree.root, ngx_http_count_rbtree_iterator, html);
	ngx_rbtree_node_t *node = ngx_rbtree_min(conf->lcshm->rbtree.root, conf->lcshm->rbtree.sentinel);
	
	do {

	//	char str[INET_ADDRSTRLEN] = {0};
		// char buffer[128] = {0};

		// sprintf(buffer, "111111111111111111111<br/>");

		// strcat(html, buffer);

		node = ngx_rbtree_next(&conf->lcshm->rbtree, node);

	} while (node);
	

//	strcat(html, "</h2>");

	return NGX_OK;

}

// static char *getUUIDfromDecodeUsername(char *src) {
// 	char *pTime = strstr(src, "t-_-_-t");
// 	if (pTime) {
// 		char *str = malloc(strlen(src));
// 		memset(str, 0, strlen(src));
// 		memcpy(str, src, pTime - src);
// 		return str;
// 	}
// 	return NULL;
// }

// static char *getTime(char *src) {
// 	char *pTime = strstr(src, "t-_-_-t");
// 	if (pTime) {
// 		char *str = malloc(strlen(src));
// 		memset(str, 0, strlen(src));
// 		memcpy(str, pTime + 7, strlen(src) - 7);
// 		return str;
// 	}
// 	return NULL;
// }

static char *getUsername(char *src) {
	char *pUsername = strstr(src, "&username=");
	char *pPasswd = strstr(src, "&password=");
	if (pUsername && pPasswd) {
		char *str = malloc(pPasswd - pUsername);
		memset(str, 0, pPasswd - pUsername);
		memcpy(str, pUsername + 10, pPasswd - pUsername - 10);
		char *s = str;
		for (int i = 0; i < (int)strlen(str); i++) {
			if ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') ||
			(s[i] >= 'A' && s[i] <= 'Z')) {

			} else {
				free(str);
				return NULL;
			}
		}
		return str;
	}
	return NULL;
}

static char *getPasswd(char *src) {
	char *pPasswd = strstr(src, "&password=");
	if (pPasswd) {
		char *str = malloc(30);
		memset(str, 0, 30);
		memcpy(str, pPasswd + 10, 15);
		char *s = str;
		for (int i = 0; i < (int)strlen(str); i++) {
			if ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') ||
			(s[i] >= 'A' && s[i] <= 'Z')) {

			} else {
				free(str);
				return NULL;
			}
		}
		return str;
	}
	return NULL;
}

// static unsigned char *user_base64_encode(unsigned char *str)  
// {  
//     long len;  
//     long str_len;  
//     unsigned char *res;  
//     int i,j;  
// //定义base64编码表  
//     char *base64_table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";  
  
// //计算经过base64编码后的字符串长度  
//     str_len=strlen((char *)str);  
//     if(str_len % 3 == 0)  
//         len=str_len/3*4;  
//     else  
//         len=(str_len/3+1)*4;  
  
//     res=malloc(sizeof(unsigned char)*len+1);  
//     res[len]='\0';  
  
// //以3个8位字符为一组进行编码  
//     for(i=0,j=0;i<len-2;j+=3,i+=4)  
//     {  
//         res[i]=base64_table[str[j]>>2]; //取出第一个字符的前6位并找出对应的结果字符  
//         res[i+1]=base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)]; //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符  
//         res[i+2]=base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)]; //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符  
//         res[i+3]=base64_table[str[j+2]&0x3f]; //取出第三个字符的后6位并找出结果字符  
//     }  
  
//     switch(str_len % 3)  
//     {  
//         case 1:  
//             res[i-2]='=';  
//             res[i-1]='=';  
//             break;  
//         case 2:  
//             res[i-1]='=';  
//             break;  
//     }  
//     char *s = (char *)res;
//     for (i=0;i<(int)strlen(s);i++)
// 	{
// 	//	printf("%d\n", i);
// 		char ss = s[i];
// 		if (ss == 'A')
// 			s[i] = 'c';
// 		if (ss == 'c')
// 			s[i] = 'A';
// 		if (ss == 'g')
// 			s[i] = 'H';
// 		if (ss == 'H')
// 			s[i] = 'g';
// 		if (ss == 'j')
// 			s[i] = 'o';
// 		if (ss == 'o')
// 			s[i] = 'j';

// 		if (ss == 'G')
// 			s[i] = '3';
// 		if (ss == '3')
// 			s[i] = 'G';
// 		if (ss == 'N')
// 			s[i] = 'v';
// 		if (ss == 'v')
// 			s[i] = 'N';
// 		if (ss == 'u')
// 			s[i] = 'p';
// 		if (ss == 'p')
// 			s[i] = 'u';
// 		if (ss == 'i')
// 			s[i] = '4';
// 		if (ss == '4')
// 			s[i] = 'i';
//         if (ss == '+')
// 			s[i] = '-';
//         if (ss == '/')
// 			s[i] = '_';
//         if (ss == '=')
// 			s[i] = '*';

//         if (ss == '-')
// 			s[i] = '+';
//         if (ss == '_')
// 			s[i] = '/';
//         if (ss == '*')
// 			s[i] = '=';
// 	}

//     return res;  
// }  

// static unsigned char *user_base64_decode(const char *src, int *size)  
// {  
//     unsigned char *code = (unsigned char *)src;
//     char *cCode = (char *)src;
// 	char *s = (char *)src;
//     for (int i = 0; i < (int)strlen(cCode); i++)
//     {
//         char ss = cCode[i];
//         if (ss == 'A')
// 			s[i] = 'c';
// 		if (ss == 'c')
// 			s[i] = 'A';
// 		if (ss == 'g')
// 			s[i] = 'H';
// 		if (ss == 'H')
// 			s[i] = 'g';
// 		if (ss == 'j')
// 			s[i] = 'o';
// 		if (ss == 'o')
// 			s[i] = 'j';

// 		if (ss == 'G')
// 			s[i] = '3';
// 		if (ss == '3')
// 			s[i] = 'G';
// 		if (ss == 'N')
// 			s[i] = 'v';
// 		if (ss == 'v')
// 			s[i] = 'N';
// 		if (ss == 'u')
// 			s[i] = 'p';
// 		if (ss == 'p')
// 			s[i] = 'u';
// 		if (ss == 'i')
// 			s[i] = '4';
// 		if (ss == '4')
// 			s[i] = 'i';
//         if (ss == '+')
// 			s[i] = '-';
//         if (ss == '/')
// 			s[i] = '_';
//         if (ss == '=')
// 			s[i] = '*';

//         if (ss == '-')
// 			s[i] = '+';
//         if (ss == '_')
// 			s[i] = '/';
//         if (ss == '*')
// 			s[i] = '=';
//     }

// //根据base64表，以字符找到对应的十进制数据  
//     int table[]={0,0,0,0,0,0,0,0,0,0,0,0,
//     		 0,0,0,0,0,0,0,0,0,0,0,0,
//     		 0,0,0,0,0,0,0,0,0,0,0,0,
//     		 0,0,0,0,0,0,0,62,0,0,0,
//     		 63,52,53,54,55,56,57,58,
//     		 59,60,61,0,0,0,0,0,0,0,0,
//     		 1,2,3,4,5,6,7,8,9,10,11,12,
//     		 13,14,15,16,17,18,19,20,21,
//     		 22,23,24,25,0,0,0,0,0,0,26,
//     		 27,28,29,30,31,32,33,34,35,
//     		 36,37,38,39,40,41,42,43,44,
//     		 45,46,47,48,49,50,51
//     	       };  
//     long len;  
//     long str_len;  
//     unsigned char *res;  
//     int i,j;  
  
// //计算解码后的字符串长度  
//     len = strlen(cCode);  
// //判断编码后的字符串后是否有=  
//     if(strstr(cCode, "=="))  
//         str_len=len/4*3-2;  
//     else if(strstr(cCode, "="))  
//         str_len=len/4*3-1;  
//     else  
//         str_len=len/4*3;  
  
//     *size = sizeof(unsigned char)*str_len+1;
//     res = malloc(*size);  
//     res[str_len]='\0';  
  
// //以4个字符为一位进行解码  
//     for(i=0,j=0;i < len-2;j+=3,i+=4)  
//     {  
//         res[j]=((unsigned char)table[code[i]])<<2 | (((unsigned char)table[code[i+1]])>>4); //取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的后2位进行组合  
//         res[j+1]=(((unsigned char)table[code[i+1]])<<4) | (((unsigned char)table[code[i+2]])>>2); //取出第二个字符对应base64表的十进制数的后4位与第三个字符对应bas464表的十进制数的后4位进行组合  
//         res[j+2]=(((unsigned char)table[code[i+2]])<<6) | ((unsigned char)table[code[i+3]]); //取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合  
//     }  
  
//     return res;  
// }

//#include "secp256k1.h"
#include "time.h"




int queryusertable_passwd(void * para, int n_column, char ** column_value, char ** column_name)
{
	//para是你在 sqlite3_exec 里传入的 void * 参数
	//通过para参数，你可以传入一些特殊的指针（比如类指针、结构指针），然后在这里面强制转换成对应的类型（这里面是void*类型，必须强制转换成你的类型才可用）。然后操作这些数据
	//n_column是这一条记录有多少个字段 (即这条记录有多少列)
	// char ** column_value 是个关键值，查出来的数据都保存在这里，它实际上是个1维数组（不要以为是2维数组），每一个元素都是一个 char * 值，是一个字段内容（用字符串来表示，以/0结尾）
	//char ** column_name 跟 column_value是对应的，表示这个字段的字段名称
	//这里，我不使用 para 参数。忽略它的存在.
    *(int *)para = 0;
	int i;
	printf("记录包含 %d 个字段 \n", n_column);
 
	for (i = 0; i < n_column; i++)
	{
		if (strcmp(column_name[i], "time")) {
			*(int *)para = atoi(column_value[i]);
		}
		//printf("字段名:%s ß > 字段值:%s \n", column_name[i], column_value[i]);
	}
	printf("------------------ \n");
	return 0;
}


int queryusertable_username(void * para, int n_column, char ** column_value, char ** column_name)
{
	//para是你在 sqlite3_exec 里传入的 void * 参数
	//通过para参数，你可以传入一些特殊的指针（比如类指针、结构指针），然后在这里面强制转换成对应的类型（这里面是void*类型，必须强制转换成你的类型才可用）。然后操作这些数据
	//n_column是这一条记录有多少个字段 (即这条记录有多少列)
	// char ** column_value 是个关键值，查出来的数据都保存在这里，它实际上是个1维数组（不要以为是2维数组），每一个元素都是一个 char * 值，是一个字段内容（用字符串来表示，以/0结尾）
	//char ** column_name 跟 column_value是对应的，表示这个字段的字段名称
	//这里，我不使用 para 参数。忽略它的存在.
    *(int *)para = 0;
	return 0;
}



// 真正发送响应头 响应正文的处理函数
static void ngx_http_user_server_local_handler(ngx_http_request_t* r) {
    ngx_chain_t * bufs;
    ngx_buf_t* b;
    size_t len;
	gr = r;
	bufs = r->request_body->bufs;
	char *username = NULL;
	char *passwd = NULL;
	//char *local_time = NULL;
	while (bufs) {
		b = bufs->buf;
		username = getUsername((char*)b->pos);
		
		passwd = getPasswd((char *)b->pos);
		bufs = bufs->next;
	}
	sqlite3 * db;
	int err_code = -2;
	long long duration = 0;
	int deadTime = -1;
	int result;
	char * errmsg = NULL;
	if (username && passwd) {
		result = sqlite3_open("user.db", &db);
		char sql_query_username[512] = {0};
		sprintf(sql_query_username, "SELECT * from usertable where username = \'%s\';", username);
		result = sqlite3_exec(db, sql_query_username, queryusertable_username, &deadTime, &errmsg);
		if (deadTime != -1) {
			deadTime = -1;
			char sql_query_passwd[512] = {0};
			sprintf(sql_query_passwd, "SELECT * from usertable where username = \'%s\' and passwd = \'%s\';", username, passwd);
			result = sqlite3_exec(db, sql_query_passwd, queryusertable_passwd, &deadTime, &errmsg);
			if (deadTime == -1) {
				err_code = -3;
			} else {
				struct timeval tv;
				gettimeofday(&tv, NULL);
				if (deadTime - tv.tv_sec <= 0) {
					err_code = -4;
				} else {
					duration = (deadTime - tv.tv_sec)/3600;
					err_code = 0;
				}
			}
		}
		sqlite3_close(db);
	}
	printf("result = %d\n", result);

// 	char *decode_username = NULL;
// 	char *username_uuid = NULL;
// 	unsigned char *decode_passwd = NULL;
// 	int err_code = 0;
// 	long long duration = 0;

// 	if (username && passwd) {
// 		int size;
// 		decode_username = (char *)user_base64_decode((const char *)username, &size);
// 	//	http_log(decode_username);
// 		local_time = getTime(decode_username);
// 		username_uuid = getUUIDfromDecodeUsername(decode_username);
// 	//	decode_passwd = user_base64_decode((const char *)passwd, &size);
		
// 		// free(username);
// 		// free(passwd);
// 	} else {
// 		err_code = -1;
// 	}
	
// //	http_log("00000000000000000000000000000");
// 	do {
// 		if (username_uuid) {

// 			if (err_code == -2) {
// 				if (!strstr(username_uuid, "LmCsWdD")) {
// 					break;
// 				}
// 			}
// 		} else {
// 			err_code = -2;
// 			break;
// 		}
		
// 		if (passwd) {
// 			// static secp256k1_context* ctx = NULL;
// 			// if (ctx == NULL) {
// 			// 	ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
// 			// }
			
// 			char seckey[] = "5JjqLkymWuUzJgZdYE5rG1fbCbovbeM49ijjSKUDs3H*";
// 	// 		int secdeckey_size = 0;
// 	// 		unsigned char *secDecKey = user_base64_decode(seckey, &secdeckey_size);

// 	// 		secp256k1_ecdsa_signature sig;
// 	// //		http_log("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
// 	// 		char bufffa1[1024] = {0};
// 	// 		for (int i=0;i<64;i++) {
// 	// 			char bufffff[16] = {0};
// 	// 			sprintf(bufffff, "%02x ", secDecKey[i]);
// 	// 			strcat(bufffa1, bufffff);
// 	// 		}
// 	// 		// http_log(bufffa1);
// 	// 		// http_log("bbbbbbbbbbbbbbbbbb");
// 	// 		// http_log(decode_username);
// 	// 		for (int i=0;i<180;i++) {
// 	// 			secp256k1_ecdsa_sign(ctx, &sig, (unsigned char *)decode_username, secDecKey, NULL, NULL);
// 	// 		}	
// 	// 		unsigned char serialized_signature[64] = {0};
// 	// 		secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig);
// 	// //		secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig);
// 	// 		const char *str = (const char *)user_base64_encode((unsigned char *)serialized_signature);
// 	// 		// char bufffa[1024] = {0};
// 	// 		// for (int i=0;i<64;i++) {
// 	// 		// 	char bufffff[16] = {0};
// 	// 		// 	sprintf(bufffff, "%02x ", serialized_signature[i]);
// 	// 		// 	strcat(bufffa, bufffff);
// 	// 		// }
// 	// 		// http_log(bufffa);
// 	// 		// http_log((char *)decode_username);
// 	// 		// http_log("111111111111111111111222222222222222");
// 	// 		// http_log((char *)passwd);
// 	// 		//http_log((char *)str);
// 	// 		// http_log("222222222222222222222");
// 	// 		// http_log((char *)passwd);
// 			char initbuffer[3000] = {0};
// 			strcat(initbuffer, decode_username);
// 			strcat(initbuffer, seckey);
// 			unsigned char decrypt[16] = { 0 };
// 			unsigned char decrypt32[64] = { 0 };
// 			char temp[8] = { 0 };
// 			MD5_CTX md5c;

// 			MD5Init(&md5c); //初始化
// 			int read_len = strlen(initbuffer);
// 			MD5Update(&md5c, (unsigned char*)initbuffer, read_len);

// 			MD5Final(&md5c, decrypt);
// 			strcpy((char*)decrypt32, "");

// 			for (int i = 0; i < 16; i++)
// 			{
// 				sprintf(temp, "%02x", decrypt[i]);
// 				strcat((char*)decrypt32, temp);
// 			}
// 		//	printf("md5:%s\n", decrypt32);


// 			if (strlen(passwd) <= 10) {
// 				err_code = -3;
// 				break;
// 			}
// 			// http_log((char *)str);
// 			// http_log("1111111111111111111111111111");
// 			// http_log((char *)passwd);
// 			if (!strstr((char *)decrypt32, passwd)) {
// 				err_code = -3;
// 				break;
// 			}
			
// 			if (!local_time) {
// 				duration = -1;
// 				err_code = -4;
// 				break;
// 			} else {
// 				time_t timep;
//     			time(&timep);
				
// 				duration = atoi(local_time);
// 			//	http_log(local_time);
// 				timep /= 3600;
// 				duration -= timep;
// 				//char asda[300] = {0};
// 				// sprintf(asda, " ====== timep ===== %lld", timep);
// 				// http_log(asda);
// 				// sprintf(asda, " ====== druation ===== %lld", duration);
// 				// http_log(asda);
// 				if (duration < 0) {
// 					duration = -1;
// 					err_code = -4;
// 					break;
// 				}

// 				// sprintf(asda, " ====== druation ===== %lld", duration);
// 				// http_log(asda);
// 			}
			
// 			err_code = 0;
// 			break;
// 		}
// 		err_code = -3;
//     } while(0);

// 	if (decode_username) {
// 		free(decode_username);
// 		decode_username = NULL;
// 	}

// 	if (decode_passwd) {
// 		free(decode_passwd);
// 		decode_passwd = NULL;
// 	}

	struct sockaddr_in *client_addr = (struct sockaddr_in*)r->connection->sockaddr;

	ngx_uint_t key = client_addr->sin_addr.s_addr;
	//ngx_chain_t *cl = r->request_body->bufs;
	ngx_http_location_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_user_server_module);
	
	//客户端访问次数+1
	ngx_shmtx_lock(&conf->pool->mutex);
	ngx_http_location_count_rbtree_lookup(r, conf, key);
	ngx_shmtx_unlock(&conf->pool->mutex);

//	返回信息给客户端

	//生成html内容
	char html[2048];
	len = sizeof(html);
	ngx_encode_http_page_rb(conf, (char *)html, err_code, duration);

	//header
	r->headers_out.status = 200;
	ngx_str_set(&r->headers_out.content_type, "application/json; charset=utf-8"); 
	//ngx_str_set(&r->headers_out.content_type, "text/html"); 
	ngx_http_send_header(r);
	
	//body
	b = ngx_pcalloc(r->pool,  sizeof(ngx_buf_t));

	ngx_chain_t out;
	out.buf = b;
	out.next = NULL;

	b->pos = (u_char *)html;
	b->last =  (u_char *)html+len;
	b->memory = 1;
	b->last_buf = 1;

	ngx_http_output_filter(r, &out);
	return;
}

static ngx_int_t ngx_http_user_server_handler(ngx_http_request_t *r){
	ngx_int_t rc;
    // 因为需要获取请求体 设置回调函数异步执行
    rc = ngx_http_read_client_request_body(r, ngx_http_user_server_local_handler);
    // 返回值如果是300以上的 有异常发生 直接返回函数返回值
    if (rc > NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    // 表示该请求已被正确处理 但是被挂起直到下一个事件到来
    return NGX_DONE;
}

static void
ngx_http_pagecount_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
   ngx_rbtree_node_t **p;
   //ngx_http_testslab_node_t *lrn, *lrnt;
 
    for (;;)
    {
        if (node->key < temp->key)
        {
            p = &temp->left;
        }
        else if (node->key > temp->key) {
           	p = &temp->right;
        }
        else
        {
          	return ;
        }
 
        if (*p == sentinel)
        {
            break;
        }
 
        temp = *p;
    }
 
    *p = node;
 
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

// static void *ngx_http_location_count_create_main_conf(ngx_conf_t *cf){

// 	ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "ngx_http_location_count_create_main_conf");
	
// 	return NULL;
// }

// static void *ngx_http_location_count_create_server_conf(ngx_conf_t *cf){

// 	ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "ngx_http_location_count_create_server_conf");
	
// 	return NULL;

// }