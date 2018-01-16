<?php

class_alias('\PHPUnit\Framework\TestCase', '\PHPUnit_Framework_TestCase');

if (!defined('OPENSSL_CONF_PATH')) {
	define('OPENSSL_CONF_PATH', '/etc/ssl/openssl.cnf');
}

abstract class SMIMETest extends PHPUnit_Framework_TestCase {
}

?>
