<?php

$output1 = shell_exec("klist 2>&1");

echo "<pre>". $output1."</pre>";


$output2 = shell_exec("klist 2>&1");

echo "<pre>". $output2."</pre>";
