#ifdef HAVE_CONFIG_H
#include "config.h" 
#endif 
#include "php.h"
#include "php_ini.h"

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>

#include "php_mini_cache.h"
#include "MiniCache.h"

zend_class_entry * miniCacheCe;

ZEND_BEGIN_ARG_INFO_EX(arg_info_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_construct, 0, 0, 2)
	ZEND_ARG_INFO(0, username)
	ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_connect, 0, 0, 3)
	ZEND_ARG_INFO(0, host)
	ZEND_ARG_INFO(0, port)
	ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_set, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_get, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_del, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_lpush, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_llen, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_list, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_ldel, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_lrange, 0, 0, 3)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, min_offset)
	ZEND_ARG_INFO(0, max_offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_hmset, 0, 0, 3)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, hash_key)
	ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_hmget, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, hash_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_hmdel, 0, 0, 2)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, hash_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_publish, 0, 0, 2)
	ZEND_ARG_INFO(0, queue)
	ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_subscribe, 0, 0, 2)
	ZEND_ARG_INFO(0, queue)
	ZEND_ARG_INFO(0, message_handler)
ZEND_END_ARG_INFO()

PHP_METHOD(MiniCache, __construct);
PHP_METHOD(MiniCache, __destruct);
PHP_METHOD(MiniCache, login);
PHP_METHOD(MiniCache, connect);
PHP_METHOD(MiniCache, set);
PHP_METHOD(MiniCache, get);
PHP_METHOD(MiniCache, del);

PHP_METHOD(MiniCache, lpush);
PHP_METHOD(MiniCache, llen);
PHP_METHOD(MiniCache, list);
PHP_METHOD(MiniCache, ldel);
PHP_METHOD(MiniCache, lrange);

PHP_METHOD(MiniCache, hmset);
PHP_METHOD(MiniCache, hmget);
PHP_METHOD(MiniCache, hmdel);

PHP_METHOD(MiniCache, publish);
PHP_METHOD(MiniCache, subscribe);

zend_function_entry MiniCacheMethods[] = {
	ZEND_ME(MiniCache, __construct, arg_construct, ZEND_ACC_CTOR | ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, __destruct, arg_info_void, ZEND_ACC_DTOR | ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, login, arg_info_void, ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, connect, arg_connect, ZEND_ACC_PUBLIC)

	ZEND_ME(MiniCache, set, arg_set, ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, get, arg_get, ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, del, arg_del, ZEND_ACC_PUBLIC)

	ZEND_ME(MiniCache, lpush, arg_lpush, ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, llen, arg_llen, ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, list, arg_list, ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, ldel, arg_del, ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, lrange, arg_lrange, ZEND_ACC_PUBLIC)
	
	ZEND_ME(MiniCache, hmset, arg_hmset, ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, hmget, arg_hmget, ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, hmdel, arg_hmdel, ZEND_ACC_PUBLIC)

	ZEND_ME(MiniCache, publish, arg_publish, ZEND_ACC_PUBLIC)
	ZEND_ME(MiniCache, subscribe, arg_subscribe, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

PHP_MINIT_FUNCTION(MiniCache) {
	zend_class_entry ce;
	INIT_CLASS_ENTRY(ce, "MiniCache", MiniCacheMethods);
	miniCacheCe = zend_register_internal_class(&ce);

	zend_declare_property_null(miniCacheCe, "fd", sizeof("fd") - 1, ZEND_ACC_PUBLIC);
	zend_declare_property_null(miniCacheCe, "host", sizeof("host") - 1, ZEND_ACC_PUBLIC);
	zend_declare_property_null(miniCacheCe, "host_len", sizeof("host_len") - 1, ZEND_ACC_PUBLIC);
	zend_declare_property_null(miniCacheCe, "port", sizeof("port") - 1, ZEND_ACC_PUBLIC);
	zend_declare_property_null(miniCacheCe, "timeout", sizeof("timeout") - 1, ZEND_ACC_PUBLIC);
	zend_declare_property_null(miniCacheCe, "username", sizeof("username") - 1, ZEND_ACC_PUBLIC);
	zend_declare_property_null(miniCacheCe, "password", sizeof("password") - 1, ZEND_ACC_PUBLIC);
}

int getFd(zval * object) {
	zval  * _fd;
	int fd;

	_fd = zend_read_property(miniCacheCe, object, "fd", sizeof("fd") - 1, 0, NULL);
	fd = Z_LVAL_P(_fd);
	return fd;
}

PHP_METHOD(MiniCache, __construct) {
	char * username, * password;
	zend_long username_len, password_len;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &username, &username_len, &password, &password_len)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(2, 2)
	Z_PARAM_STRING(username, username_len)
	Z_PARAM_STRING(password, password_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	zend_update_property_string(miniCacheCe, getThis(), "username", sizeof("username") - 1, username);
	zend_update_property_string(miniCacheCe, getThis(), "password", sizeof("password") - 1, password);
}

PHP_METHOD(MiniCache, __destruct) {
	close(getFd(getThis()));
}

PHP_METHOD(MiniCache, connect) {
	char * host;
	long host_len, port, timeout;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "sll", &host, &host_len, &port, &timeout) == FAILURE) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STRING(host, host_len)
		Z_PARAM_LONG(port)
		Z_PARAM_LONG(timeout)
	ZEND_PARSE_PARAMETERS_END();
#endif

	unsigned long fd = socket(PF_INET, SOCK_STREAM, 0);
	assert(fd >= 0);

	struct sockaddr_in serveraddr;
	serveraddr.sin_family = PF_INET;
	serveraddr.sin_port = htons(port);
	inet_aton(host, &serveraddr.sin_addr);

	int ret = connect(fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "connect failed");
	}

	zend_update_property_string(miniCacheCe, getThis(), "host", sizeof("host") - 1, host);
	zend_update_property_long(miniCacheCe, getThis(), "host_len", sizeof("host_len") - 1, host_len);
	zend_update_property_long(miniCacheCe, getThis(), "port", sizeof("port") - 1, port);
	zend_update_property_long(miniCacheCe, getThis(), "timeout", sizeof("timeout") - 1, timeout);
	zend_update_property_long(miniCacheCe, getThis(), "fd", sizeof("fd") - 1, fd);
	
	zend_call_method(getThis(), miniCacheCe, NULL, "login", sizeof("login") - 1, (zval *)&ret, 0, NULL, NULL);

	RETURN_TRUE;
}

PHP_METHOD(MiniCache, login) {
    zval * z_username = zend_read_property(miniCacheCe, getThis(), "username", sizeof("username") - 1, 0, NULL);
    char * username = Z_STRVAL_P(z_username);
    zval * z_password = zend_read_property(miniCacheCe, getThis(), "password", sizeof("password") - 1, 0, NULL);
    char * password = Z_STRVAL_P(z_password);

    int fd = getFd(getThis());
    int send_buff_len = 10 + strlen(username) + strlen(password);
    char * send_buff = (char *)malloc(send_buff_len);
    memset(send_buff, 0, send_buff_len);
    sprintf(send_buff, "login %s %s", username, password);
    int ret = send(fd, send_buff, strlen(send_buff) + 1, 0); 
    free(send_buff);
    if (ret < 0) {
        php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
    }   

    char recv_buff[RECV_BUFF_SIZE];
    memset(recv_buff, 0, RECV_BUFF_SIZE);
    ret = recv(fd, recv_buff, RECV_BUFF_SIZE, 0); 
    if (ret < 0) {
        php_error_docref(NULL, E_ERROR, "%s", "login failed");
    }   

    if (strncmp(recv_buff, SUCCESS, strlen(SUCCESS)) == 0) {
        RETURN_LONG(1);
    }   

    php_error_docref(NULL, E_ERROR, "%s", "login failed");
}

PHP_METHOD(MiniCache, set) {
    char * key, *value;
    zend_long key_len, value_len;
#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key, &key_len, &value, &value_len)) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(key, key_len)
    Z_PARAM_STRING(value, value_len)
    ZEND_PARSE_PARAMETERS_END();
#endif

    int fd = getFd(getThis());
    int send_buff_len = 10 + key_len + value_len;
    char * send_buff = (char *)malloc(send_buff_len);
    memset(send_buff, 0, send_buff_len);
    sprintf(send_buff, "set %s %s", key, value);
    int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
    free(send_buff);
    if (ret < 0) {
        php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
    }

    char recv_buff[RECV_BUFF_SIZE];
    memset(recv_buff, 0, RECV_BUFF_SIZE);
    ret = recv(fd, recv_buff, RECV_BUFF_SIZE, 0);
    if (ret < 0) {
        php_error_docref(NULL, E_ERROR, "%s", "set failed, receive message failed");
    }

    if (strncmp(recv_buff, SUCCESS, strlen(SUCCESS)) != 0) {
        php_error_docref(NULL, E_ERROR, "%s", recv_buff);
    }

    RETURN_TRUE;
}

PHP_METHOD(MiniCache, get) {
    char * key;
    zend_long key_len;
#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &key_len)) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(1, 1)
    Z_PARAM_STRING(key, key_len)
    ZEND_PARSE_PARAMETERS_END();
#endif

    int fd = getFd(getThis());
    int send_buff_len = 10 + key_len;
    char * send_buff = (char *)malloc(send_buff_len);
    memset(send_buff, 0, send_buff_len);
    sprintf(send_buff, "get %s", key);
    int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
    free(send_buff);
    if (ret < 0) {
        php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
    }

    zend_string * recv_buff;
    char recv_item[RECV_BUFF_SIZE];
    memset(recv_item, 0, RECV_BUFF_SIZE);

    while((ret = recv(fd, recv_item, RECV_BUFF_SIZE - 1, 0)) > 0) {
        recv_buff = strpprintf(0, "%s%s", ZSTR_VAL(recv_buff), recv_item);
        if (ret < RECV_BUFF_SIZE - 1) {
            break;
        }
    }

    char * recv_buff_ret = ZSTR_VAL(recv_buff);
    if (strncmp(recv_buff_ret, ERROR, strlen(ERROR)) == 0) {
        php_error_docref(NULL, E_ERROR, "%s", recv_buff);
    }

    RETURN_STRING(recv_buff_ret);
}

PHP_METHOD(MiniCache, del) {
	char * key;
	zend_long key_len;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &key_len)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(1, 1)
	Z_PARAM_STRING(key, key_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 10 + key_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "del %s", key);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    char recv_buff[RECV_BUFF_SIZE];
    memset(recv_buff, 0, RECV_BUFF_SIZE);
	ret = recv(fd, recv_buff, RECV_BUFF_SIZE, 0);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "del failed, receive message faild");
	}

	if (strncmp(recv_buff, ERROR, strlen(ERROR)) == 0) {
		php_error_docref(NULL, E_ERROR, "%s", recv_buff);
	}

	RETURN_TRUE;	
}

PHP_METHOD(MiniCache, lpush) {
	char * key, *value;
	zend_long key_len, value_len;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key, &key_len, &value, &value_len)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(2, 2)
	Z_PARAM_STRING(key, key_len)
	Z_PARAM_STRING(value, value_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 10 + key_len + value_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "lpush %s %s", key, value);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    char recv_buff[RECV_BUFF_SIZE];
    memset(recv_buff, 0, RECV_BUFF_SIZE);
	ret = recv(fd, recv_buff, RECV_BUFF_SIZE, 0);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, receive message failed"); 
	} 

	if (strncmp(recv_buff, ERROR, strlen(ERROR)) == 0) {
		php_error_docref(NULL, E_ERROR, "%s", recv_buff);
	}

	RETURN_TRUE;	
}

PHP_METHOD(MiniCache, llen) {
	char * key;
	zend_long key_len;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &key_len)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(1, 1)
	Z_PARAM_STRING(key, key_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 10 + key_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "llen %s", key);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    char recv_buff[RECV_BUFF_SIZE];
    memset(recv_buff, 0, RECV_BUFF_SIZE);
	ret = recv(fd, recv_buff, RECV_BUFF_SIZE, 0);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, receive message failed");
	}


	if (strncmp(recv_buff, ERROR, strlen(ERROR)) == 0) {
		php_error_docref(NULL, E_ERROR, "%s", recv_buff);
	}

	RETURN_STRING(recv_buff);
}

PHP_METHOD(MiniCache, list) {
	char * key;
	zend_long key_len;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &key_len)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(1, 1)
	Z_PARAM_STRING(key, key_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 10 + key_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "list %s", key);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    zend_string * recv_buff;
    char recv_item[RECV_BUFF_SIZE];
    memset(recv_item, 0, RECV_BUFF_SIZE);

    while((ret = recv(fd, recv_item, RECV_BUFF_SIZE - 1, 0)) > 0) {
        recv_buff = strpprintf(0, "%s%s", ZSTR_VAL(recv_buff), recv_item);
        if (ret < RECV_BUFF_SIZE - 1) {
            break;
        }
    }

    char * recv_buff_ret = ZSTR_VAL(recv_buff);
    if (strncmp(recv_buff_ret, ERROR, strlen(ERROR)) == 0) {
        php_error_docref(NULL, E_ERROR, "%s", recv_buff);
    }

    RETURN_STRING(recv_buff_ret);
}


PHP_METHOD(MiniCache, ldel) {
	char * key;
	zend_long key_len, offset;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "sl", &key, &key_len, &offset)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(2, 2)
	Z_PARAM_STRING(key, key_len)
	Z_PARAM_LONG(offset)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 15 + key_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "ldel %s %d", key, offset);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    char recv_buff[RECV_BUFF_SIZE];
    memset(recv_buff, 0, RECV_BUFF_SIZE);
	ret = recv(fd, recv_buff, RECV_BUFF_SIZE, 0);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "ldel failed, receive message failed");
	}

	if (strncmp(recv_buff, ERROR, strlen(ERROR)) == 0) {
		php_error_docref(NULL, E_ERROR, "%s", recv_buff);
	}

	RETURN_TRUE;	
}

PHP_METHOD(MiniCache, lrange) {
	char * key;
	zend_long key_len, min_offset, max_offset;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "sll", &key, &key_len, &min_offset, &max_offset)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(3, 3)
	Z_PARAM_STRING(key, key_len)
	Z_PARAM_LONG(min_offset)
	Z_PARAM_LONG(max_offset)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 25 + key_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "lrange %s %d %d", key, min_offset, max_offset);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    zend_string * recv_buff;
    char recv_item[RECV_BUFF_SIZE];
    memset(recv_item, 0, RECV_BUFF_SIZE);

    while((ret = recv(fd, recv_item, RECV_BUFF_SIZE - 1, 0)) > 0) {
        recv_buff = strpprintf(0, "%s%s", ZSTR_VAL(recv_buff), recv_item);
        if (ret < RECV_BUFF_SIZE - 1) {
            break;
        }
    }

    char * recv_buff_ret = ZSTR_VAL(recv_buff);
    if (strncmp(recv_buff_ret, ERROR, strlen(ERROR)) == 0) {
        php_error_docref(NULL, E_ERROR, "%s", recv_buff);
    }

    RETURN_STRING(recv_buff_ret);
}

PHP_METHOD(MiniCache, hmset) {
	char * key, * hash_key, * value;
	zend_long key_len, hash_key_len, value_len;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss", &key, &key_len, &hash_key, &hash_key_len, &value, &value_len)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(3, 3)
	Z_PARAM_STRING(key, key_len)
	Z_PARAM_STRING(hash_key, hash_key_len)
	Z_PARAM_STRING(value, value_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 10 + key_len + hash_key_len + value_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "hmset %s %s %s", key, hash_key, value);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    char recv_buff[RECV_BUFF_SIZE];
    memset(recv_buff, 0, RECV_BUFF_SIZE);
	ret = recv(fd, recv_buff, RECV_BUFF_SIZE, 0);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "hmset failed, receive message failed");
	}

	if (strncmp(recv_buff, ERROR, strlen(ERROR)) == 0) {
		php_error_docref(NULL, E_ERROR, "%s", recv_buff);
	}

	RETURN_TRUE;	
}

PHP_METHOD(MiniCache, hmget) {
	char * key, * hash_key;
	zend_long key_len, hash_key_len;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key, &key_len, &hash_key, &hash_key_len)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(2, 2)
	Z_PARAM_STRING(key, key_len)
	Z_PARAM_STRING(hash_key, hash_key_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 10 + key_len + hash_key_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "hmget %s %s", key, hash_key);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    zend_string * recv_buff;
    char recv_item[RECV_BUFF_SIZE];
    memset(recv_item, 0, RECV_BUFF_SIZE);

    while((ret = recv(fd, recv_item, RECV_BUFF_SIZE - 1, 0)) > 0) {
        recv_buff = strpprintf(0, "%s%s", ZSTR_VAL(recv_buff), recv_item);
        if (ret < RECV_BUFF_SIZE - 1) {
            break;
        }
    }

    char * recv_buff_ret = ZSTR_VAL(recv_buff);
    if (strncmp(recv_buff_ret, ERROR, strlen(ERROR)) == 0) {
        php_error_docref(NULL, E_ERROR, "%s", recv_buff);
    }

    RETURN_STRING(recv_buff_ret);
}

PHP_METHOD(MiniCache, hmdel) {
	char * key, * hash_key;
	zend_long key_len, hash_key_len;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key, &key_len, &hash_key, &hash_key_len)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(2, 2)
	Z_PARAM_STRING(key, key_len)
	Z_PARAM_STRING(hash_key, hash_key_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 10 + key_len + hash_key_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "hmdel %s %s", key, hash_key);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    char recv_buff[RECV_BUFF_SIZE];
    memset(recv_buff, 0, RECV_BUFF_SIZE);
	ret = recv(fd, recv_buff, RECV_BUFF_SIZE, 0);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "hmdel failed, receive message failed");
	}

	if (strncmp(recv_buff, ERROR, strlen(ERROR)) == 0) {
		php_error_docref(NULL, E_ERROR, "%s", recv_buff);
	}

	RETURN_TRUE;	
}

PHP_METHOD(MiniCache, publish) {
	char * queue, * message;
	zend_long queue_len, message_len;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &queue, &queue_len, &message, &message_len)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(2, 2)
	Z_PARAM_STRING(queue, queue_len)
	Z_PARAM_STRING(message, message_len)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 10 + queue_len + message_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "publish %s %s", queue, message);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    char recv_buff[RECV_BUFF_SIZE];
    memset(recv_buff, 0, RECV_BUFF_SIZE);
	ret = recv(fd, recv_buff, RECV_BUFF_SIZE, 0);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "publish failed, receive message failed");
	}

	if (strncmp(recv_buff, ERROR, strlen(ERROR)) == 0) {
		php_error_docref(NULL, E_ERROR, "%s", recv_buff);
	}

	RETURN_TRUE;
}

PHP_METHOD(MiniCache, subscribe) {
	char * queue;
	zval * message_handler;
	zend_long queue_len;
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz", &queue, &queue_len, &message_handler)) {
		RETURN_FALSE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(2, 2)
	Z_PARAM_STRING(queue, queue_len)
	Z_PARAM_ZVAL(message_handler)
	ZEND_PARSE_PARAMETERS_END();
#endif

	int fd = getFd(getThis());
	int send_buff_len = 10 + queue_len;
	char * send_buff = (char *)malloc(send_buff_len);
	memset(send_buff, 0, send_buff_len);
	sprintf(send_buff, "subscribe %s", queue);
	int ret = send(fd, send_buff, strlen(send_buff) + 1, 0);
	free(send_buff);
	if (ret < 0) {
		php_error_docref(NULL, E_ERROR, "%s", "set failed, send command failed");
	}

    char recv_item[RECV_BUFF_SIZE];
    memset(recv_item, 0, RECV_BUFF_SIZE);
	zval args[1], retval;
	while (1) {
		char * recv_buff = (char *)malloc(RECV_BUFF_SIZE);
		int recv_buff_size = RECV_BUFF_SIZE;
		memset(recv_buff, 0, RECV_BUFF_SIZE);

		int recv_size = 0;
    	while((ret = recv(fd, recv_item, RECV_BUFF_SIZE - 1, 0)) > 0) {
			recv_size += ret;
			if (recv_size < RECV_BUFF_SIZE - 1) {
				strncpy(recv_buff, recv_item, recv_size);
				break;
			}

			if (recv_size >= recv_buff_size) {
				char * recv_buff_tmp = recv_buff;
				recv_buff_size = recv_buff_size * 2;
				recv_buff = (char *)malloc(recv_buff_size);
				strcpy(recv_buff, recv_buff_tmp);
				strcat(recv_buff, recv_item);
				free(recv_buff_tmp);
			} else {
				strcat(recv_buff, recv_item);
			}


    	    if (ret < RECV_BUFF_SIZE - 1) {
    	        break;
    	    }
    	}

   		if (strncmp(recv_buff, ERROR, strlen(ERROR)) == 0) {
   		    php_error_docref(NULL, E_ERROR, "%s", recv_buff);
   		}

		ZVAL_STRINGL(&args[0], recv_buff, recv_size);
		call_user_function_ex(EG(function_table), NULL, message_handler, &retval, 1, args, 1, NULL);
		free(recv_buff);
	}
}

