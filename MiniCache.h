#ifndef __MINI_CACHE_H__
#define __MINI_CACHE_H__
#define RECV_BUFF_SIZE 1024
#define SEND_BUFF_SIZE 1024
#define SUCCESS "SUCCESS"
#define ERROR "ERROR"

extern zend_class_entry * miniCache;
PHP_METHOD(MiniCache, __construct);
PHP_METHOD(MiniCache, __destruct);
PHP_METHOD(MiniCache, login);
PHP_METHOD(MiniCache, clean_recv_buff);
PHP_METHOD(MiniCache, clean_send_buff);
PHP_METHOD(MiniCache, connect);
PHP_METHOD(MiniCache, set);
PHP_METHOD(MiniCache, get);
PHP_METHOD(MiniCache, del);
PHP_METHOD(MiniCache, lpush);
PHP_METHOD(MiniCache, llen);
PHP_METHOD(MiniCache, list);
PHP_METHOD(MiniCache, ldel);
PHP_METHOD(MiniCache, lrange);
PHP_METHOD(MiniCache, publish);
PHP_METHOD(MiniCache, subscribe);
PHP_METHOD(MiniCache, subscribe_test);
PHP_MINIT_FUNCTION(MiniCache);

#endif
