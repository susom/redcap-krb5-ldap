<?php

/*  STANFORD CUSTOM: Profile
	FILENAME: 	redcap_lookup.php
	ACTION:		performs an ldap query based on input parameters - this should be blocked behind a firewall

		&userid=	(ldap query) - it searches for uid, alternate sunetids, stanford email prefix, and complete email
		?only=   	(comma-separated list of return attributes - defaults to uid,mail,displayname,sudisplaynamelast,sudisplaynamefirst)
		?token=		(an application specific token that is required to use this service)
		?exact=		(if true, then it only looks for uid=$userid and not for other possible matches)

	EXAMPLE:	https://med.stanford.edu/qualtrics-dev/Stanford-LDAP/redcap_lookup.php
					?token=0dWhFQtgZN7VkCnDyzsoyZFoZGqKE4oALWMgs2K6JBkRZWS1dN
					&userid=gomathik
					&only=uid,mail
			=>	{"count":1,"1":{"uid":"gomathik","mail":"gomathik@stanford.edu"}}

	**WARNING** If this file returns something other than nothing or a json object, it will cause a generic REDCap error.

	{"count":1,"1":{"uid":"scweber","sudisplaynamefirst":"Susan","sudisplaynamelast":"Weber","mail":"scweber@stanford.edu"}}

*/

require_once("secure/LDAP.php");

define('LOG_PATH',  "/var/log/webtools/");
define('LOG_PREFIX',"redcap_lookup");
define('DEBUG',	    "false");

//DEBUG
//ECHO '{"count":1,"1":{"uid":"andy123","sudisplaynamefirst":"Andrew","sudisplaynamelast":"Martin","mail":"andy123@stanford.edu"}}';
//exit;

/* Old Authorized Addresses

"Todd's Server" =>          "/171\.65\.57\.11/",
"Stanford Wifi" =>          "/10\.39\./",
"Stanford LAN"  =>          "/^171\.65\./",

*/

$REDCAP_AUTHORIZED_IP_ADDRESSES = Array(
	"cci-webapp-devrc-02" =>    "/172\.25\.104\.40/",
	"cci-webapp-securerc-02" => "/172\.25\.104\.84/",
	"cci-webapp-devrc-03" =>    "/172\.25\.104\.92/",
	"temp" =>		"/.*/"
);

//This is a unique token that is embedded in the profile module as an added precaution
define('REDCAP_TOKEN',"0dWhFQtgZN7VkCnDyzsoyZFoZGqKE4oALWMgs2K6JBkRZWS1dN");

$userid = 	isset($_REQUEST['userid'])	? $_REQUEST['userid'] : "";
$only =  	isset($_REQUEST['only']) 	? $_REQUEST['only'] 	: "uid,mail,displayname,sudisplaynamelast,sudisplaynamefirst";		//default to uid return only
$token = 	isset($_REQUEST['token']) 	? $_REQUEST['token'] 	: "";
$exact =	isset($_REQUEST['exact'])	? strtolower($_REQUEST['exact'])	: "";

//this should only be called from the actual redcap server.

if (!validateIP($REDCAP_AUTHORIZED_IP_ADDRESSES)) {
	$error = "Request coming from unauthorized ip address.\t".$_SERVER['QUERY_STRING'];
	returnError($error);
}

//validate token (a second precaution)
if (REDCAP_TOKEN != $token) {
	$error = "Invalid token: $token in\t".$_SERVER['QUERY_STRING'];
	returnError($error);
}

if ($userid == "") {
	$error = "Missing userid for REDCap query in \t".$_SERVER['QUERY_STRING'];
	returnError($error);
}
if ($exact == "true") {
	$filter="uid=$userid";
} else {
	//in cases where people use an alias as email (andy.b.martin@stanford.edu, we need to strip the @stanford.edu for the match to work)
	$userid_stripped = preg_replace('/([^@]*)@(.*stanford.edu)/i','${1}',$userid);
	$filter="(|(uid=$userid_stripped)(susunetid=$userid_stripped)(mail=$userid_stripped@stanford.edu)(mail=$userid_stripped))";	//search by sunet or mail
	//$filter="(|(uid=$userid)(susunetid=$userid)(mail=$userid@stanford.edu)(mail=$userid))";	//search by sunet or mail
}
if ( !isset( $ldap ) ) $ldap = new LDAP();

//echo "filter: $filter, only: $only<hr>";

$results = Array();
//$rs = $ldap->query($filter, explode(",",$only));
$rs = $ldap->query($filter);
if ( $rs ) {
	$numRows = $ldap->getNumRows($rs);
	$i=1;
	while ($row=$ldap->getRow($rs)) {
		if ( isset ($row['uid'] ) ) {
			$arrResult = Array();
			$arrResult['uid'] = $row['uid'];
			if (isset( $row['displayname'] )) 		$arrResult['displayname'] = $row['displayname'];
			if (isset( $row['sudisplaynamefirst'] )) 	$arrResult['sudisplaynamefirst'] = $row['sudisplaynamefirst'];
			if (isset( $row['sudisplaynamelast'] )) 	$arrResult['sudisplaynamelast'] = $row['sudisplaynamelast'];
			if (isset( $row['mail'] )) 			$arrResult['mail'] = $row['mail'];
			$results[$i] = $arrResult;
			$i++;
		}
	}
	array_unshift_assoc($results, 'count', count($results));
}

$output = json_encode($results);

echo $output;

logSuccess($output);

function logSuccess($msg) {
	//log to text file
	file_put_contents( LOG_PATH . date( 'Y-m-' ) . LOG_PREFIX . '-success.log',
		date( 'Y-m-d H:i:s' ) . "\t" . getIP() . "\t" . $_SERVER['QUERY_STRING'] . "\t" . $msg . "\n", FILE_APPEND );
}

function returnError($error) {
		$errorMsg = $error;

		//log to text file
		file_put_contents( LOG_PATH . date( 'Y-m-d-' ) . LOG_PREFIX . '-errors.log',
			date( 'Y-m-d H:i:s' ) . "\t" . getIP() ."\t" . $errorMsg . "\n", FILE_APPEND );

		//Return error to screen
		if (DEBUG == "true") {
			$returnArray = Array("error" => $errorMsg);
		} else {
			$returnArray = Array("error" => "Please notify redcap-help@lists.stanford.edu of an error in redcap_lookup.php");
		}
		echo (json_encode($returnArray));
		exit;
}

function validateIP($allowedIPs) {
	// validate source IP
	$IPallowed = false;
	$currentIP = getIP();
	foreach($allowedIPs as $label => $ip) {
	   if (preg_match($ip, $currentIP)) {
		  $IPallowed = true;
		  break;
	   }
	}
	return $IPallowed;
}

// Get the calling IP address
function getIP() {
	$result = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
	$result = implode(", ",array_unique(explode(", ",$result)));	//filter out duplicates
	return $result;
}


function array_unshift_assoc(&$arr, $key, $val)
{
    $arr = array_reverse($arr, true);
    $arr[$key] = $val;
	$arr = array_reverse($arr, true);
	//return;
}

?>