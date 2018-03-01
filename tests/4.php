<?php
    $object = new MiniCache("admin", "admin@minicache@123");
    $ret = $object->connect("127.0.0.1", 12345, 1);
    if ($ret == FALSE) {
        throw new \Exception("conncet failed");
    }

    $object->set("johnny", "wesleyxxxxxx");
    var_dump($object->get("johnny"));
    $object->del("johnny");
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

