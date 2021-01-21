<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
require_once (__DIR__ ."/vendor/autoload.php");
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

echo $_ENV['REDCAP_TOKEN'];
$output1 = shell_exec("klist 2>&1");

echo "<pre>". $output1."</pre>";


$output2 = shell_exec("klist 2>&1");

echo "<pre>". $output2."</pre>";
