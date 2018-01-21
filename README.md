# php_mini_cache
this is php extension for minicache

## required
- >= php7.0
- mini_cache is inneed
[https://github.com/johnnylei/mini_cache.git](https://github.com/johnnylei/mini_cache.git)

## usage
```
sudo ./install-sh
```
如果上面的安装错误，请检查是否php的版本有问题，如果版本没有问题请打开install-sh,查看phpize和php-config的路劲是否有问题

## demo 
```
<?php
    $object = new MiniCache("admin", "admin@minicache@123");
    $ret = $object->connect("127.0.0.1", 12345, 1); 
    if ($ret == FALSE) {
        throw new \Exception("conncet failed");
    }   

    $object->set("johnny", "wesleyxxxxxx");
    $object->del("johnny");
//  $str = $object->get("johnny");
    $object->lpush("johnny", "xxx");
    $object->lpush("johnny", "sss");
    $object->lpush("johnny", "zzz");
    var_dump($object->llen("johnny"));
    var_dump($object->list("johnny"));
    var_dump($object->lrange("johnny", 0, 1));
    $object->ldel("johnny", 1); 
    var_dump($object->list("johnny"));

    $object->hmset("wesley", "a1", "aaa");
    $object->hmset("wesley", "b1", "bbb");
    $object->hmset("wesley", "c1", "ccc");
    var_dump($object->hmget("wesley", "c1"));
    var_dump($object->hmdel("wesley", "c1"));
    $object->publish("que2", "hellojohnny");

    $object->subscribe("que1", function($message) {
        var_dump($message);
    }); 
?>

```
