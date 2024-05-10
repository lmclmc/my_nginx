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
		ngx_string("user_server_key"),
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

ngx_module_t ngx_http_user_server_key_module = {

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
	ngx_str_t name = ngx_string("location_count_slab_key");

	lconf->shmsize = 128*1024;

	//申请一块共享内存，存入模块数据
	//业务：统计客户端访问次数
	//因为客户端每次访问资源的时候可能在nginx的不同work进程中，因此把访问次数存放在共享内存中方便任意进程访问
	ngx_shm_zone_t *zone = ngx_shared_memory_add(cf, &name, lconf->shmsize, &ngx_http_user_server_key_module);
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
	// sprintf(html, "{\"code\": %d, \"data\": {\"access_token\": \"A8A44C5E59D19816F341F790F2D53C58\", \"vip_else\": %d, \"userid\": 4029, \"time\": 1714753694}, \"sign\":\"DA361986676E8A4864370A2C882DF79A\", \"msg\": \"login success1\"}",
	// err_code, duration);

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
	char *pKey = strstr(src, "&key=");

	if (pPasswd && pKey) {
		char *str = malloc(pKey - pPasswd);
		memset(str, 0, pKey - pPasswd);
		memcpy(str, pPasswd + 10, pKey - pPasswd - 10);
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

static char *getKey(char *src) {
	char *pKey = strstr(src, "&key=");

	if (pKey) {
		char *str = malloc(30);
		memset(str, 0, 30);
		memcpy(str, pKey + 5, 10);
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


#include <stdlib.h>


int querykeytable(void * para, int n_column, char ** column_value, char ** column_name)
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
		if (strcmp(column_name[i], "TIME")) {
			*(int *)para = atoi(column_value[i]);
		}
		//printf("字段名:%s ß > 字段值:%s \n", column_name[i], column_value[i]);
	}
	printf("------------------ \n");
	return 0;
}

int queryusertable(void * para, int n_column, char ** column_value, char ** column_name)
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
		if (strcmp(column_name[i], "TIME")) {
			*(int *)para = atoi(column_value[i]);
		}
		//printf("字段名:%s ß > 字段值:%s \n", column_name[i], column_value[i]);
	}
	printf("------------------ \n");
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
	char *pKey = NULL;
	while (bufs) {
		b = bufs->buf;
		username = getUsername((char*)b->pos);
		passwd = getPasswd((char *)b->pos);
		pKey = getKey((char *)b->pos);
		bufs = bufs->next;
	}
	char * errmsg = NULL;
	int err_code = -2;
	int result = 0;
	sqlite3 * db;
	if (username && passwd && pKey) {
		result = sqlite3_open("user.db", &db);
		char sql_query[512] = {0};
		sprintf(sql_query, "SELECT * from keytable where key = '%s';", pKey);

		int queryActivationTime = -1;
		result = sqlite3_exec(db, sql_query, querykeytable, &queryActivationTime, &errmsg);
		//如果激活时间为0代表未激活,执行激活操作
		if (queryActivationTime == 0) {
			char sql_update[512] = {0};
			struct timeval tv;
    		gettimeofday(&tv, NULL);
			int asddqwtime = tv.tv_sec;
			sprintf(sql_update, "UPDATE keytable SET username = \'%s\', passwd = \'%s\', time = \'%d\' where key = '%s';",
			username, passwd, asddqwtime, pKey);

			char sql_query_user_table[512] = {0};
			int deadTime = -1;
			sprintf(sql_query_user_table, "SELECT * from usertable where username = \'%s\' and passwd = \'%s\';", username, passwd);
			result = sqlite3_exec(db, sql_query, queryusertable, &deadTime, &errmsg);
			
			if (deadTime == -1) {
				//如果没有找到对应用户名密码则走这里，创建新的用户名密码
				char sql_insert_user_table[512] = {0};
				int ttttime = tv.tv_sec + 86400;
				sprintf(sql_insert_user_table, "INSERT INTO usertable(username, passwd, time) VALUES(\"%s\", \"%s\", \"%d\");", username, passwd, ttttime);
				result = sqlite3_exec(db, sql_insert_user_table, 0, 0, &errmsg);
			} else {
				//如果找到对应用户名密码则走这里,更新用户的到期时间
				char sql_update_user_table[512] = {0};
				if (tv.tv_sec > deadTime) {
					deadTime = tv.tv_sec + 86400;
				} else {
					deadTime += 86400;
				}
				sprintf(sql_update_user_table, "UPDATE keytable SET time = \'%d\' where username = '%s' and passwd = '%s';",
						deadTime, username, passwd);
				result = sqlite3_exec(db, sql_update_user_table, 0, 0, &errmsg);
			}
			err_code = 1;
		}

		sqlite3_close(db);
	}
	printf("%d\n", result);

	struct sockaddr_in *client_addr = (struct sockaddr_in*)r->connection->sockaddr;

	ngx_uint_t key = client_addr->sin_addr.s_addr;
	//ngx_chain_t *cl = r->request_body->bufs;
	ngx_http_location_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_user_server_key_module);
	
	//客户端访问次数+1
	ngx_shmtx_lock(&conf->pool->mutex);
	ngx_http_location_count_rbtree_lookup(r, conf, key);
	ngx_shmtx_unlock(&conf->pool->mutex);

//	返回信息给客户端

	//生成html内容
	char html[2048];
	len = sizeof(html);
	ngx_encode_http_page_rb(conf, (char *)html, err_code, 10);

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