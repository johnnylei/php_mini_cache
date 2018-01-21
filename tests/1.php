<?php
	$object = new MiniCache("admin", "admin@minicache@123");
	$ret = $object->connect("127.0.0.1", 12345, 1);
	if ($ret == FALSE) {
		throw new \Exception("conncet failed");
	}

	$object->set("johnny", "nicolasxxxxxx");
	$object->del("johnny");
// 	$str = $object->get("johnny");
	$object->lpush("johnny", "xxx");
	$object->lpush("johnny", "sss");
	$object->lpush("johnny", "zzz");
	var_dump($object->llen("johnny"));
	var_dump($object->list("johnny"));
	var_dump($object->lrange("johnny", 0, 1));
	$object->ldel("johnny", 1);
	var_dump($object->list("johnny"));

	$object->hmset("nicolas", "a1", "aaa");
	$object->hmset("nicolas", "b1", "bbb");
	$object->hmset("nicolas", "c1", "ccc");
	var_dump($object->hmget("nicolas", "c1"));
	var_dump($object->hmdel("nicolas", "c1"));
	$object->publish("que2", "hellojohnny");

	$object->subscribe("que1", function($message) {
		var_dump($message);
	});
?>
