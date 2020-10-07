<?php
/*
	USAGE IN EXCEL:  =LDAP(B4,"ou", "LqjcQQei95e2tLjgQZr7KnHcCejJTLea")

	FILENAME: 	ldap_lookup.php
	ACTION:		performs an ldap query based on input parameters - this should be blocked behind a firewall

		&userid=	(ldap query) - it searches for uid, alternate sunetids, stanford email prefix, and complete email
		?only=   	(comma-separated list of return attributes - defaults to uid,mail,sudisplaynamelast,sudisplaynamefirst)
		?token=		(an application specific token that is required to use this service)
		?exact=		(if true, then it only looks for uid=$userid and not for other possible matches)

	EXAMPLE:	http://med.stanford.edu/webtools-dev/stanford_ldap/ldap_lookup.php
					?token=0dWhFQtgZN7VkCnDyzsoyZFoZGqKE4oALWMgs2K6JBkRZWS1dN
					&userid=gomathik
					&only=uid,mail
			=>	{"count":1,"1":{"uid":"gomathik","mail":"gomathik@stanford.edu"}}

	**WARNING** If this file returns something other than nothing or a json object, it will cause a generic REDCap error.

	{"count":1,
		"1":{
			"sudisplaynamefirst":"Andrew",
			"sudisplaynamelast":"Martin",
			"uid":"andy123",
			"mail":"andy123@stanford.edu",
			"telephonenumber":"(650) 380-3405",
			"ou":"Center for Clinical Informatics",
			"suaffiliation":"stanford:staff:nonactive | stanford:staff"}
			"sugwaffiliation1":"stanford:staff",
			}

	{"count":1,
		"1":
			{"suregisteredname":"Andrew B Martin",
			"sudisplaynamefirst":"Andrew",
			"objectclass":["suPerson","organizationalPerson","inetOrgPerson","person"],
			"suuniqueidentifier":"DR387F350 ",
			"suregisterednamelf":"Martin, Andrew B",
			"sudisplaynamelast":"Martin",
			"sudisplaynamemiddle":"B",
			"sn":"martin",
			"suregid":"1ed1b712426b4a46800928edc1f747a2",
			"uid":"andy123",
			"suothername":"Andy Martin",
			"cn":["andrew martin","andy martin","andrew b martin"],
			"givenname":["andrew","andy"],
			"displayname":"Andrew B Martin",
			"sudisplaynamelf":"Martin, Andrew B",
			"susunetid":["andy.b.martin","andy123"],
			"mail":"andy123@stanford.edu",
			"telephonenumber":"(650) 380-3405",
			"postaladdress":"1265 Welch Road, Medical School Office Building (MSOB), xc22, Stanford, California 94305-5412",
			"sumailcode":"5412",
			"ou":"Center for Clinical Informatics",
			"suaffiliation":["stanford:staff:nonactive","stanford:staff"],
			"suprivilegegroup":["med-publish:pacific","med-irt:dcswiki",...]
			}
	}


*/

require_once("secure/LDAP.php");

define('LOG_PATH',   "/var/log/webtools/");
define('LOG_PREFIX', "ldap_lookup");
define('DEBUG',	     "false");


//$AUTHORIZED_IP_ADDRESSES = Array(
//	"Stanford Wifi" 		=> "/10\.39\./",
//	"Stanford LAN"  		=> "/^171\.65\./",
//	"cci-webapp-devrc-02" 		=> "/172\.25\.104\.89/");

$AUTHORIZED_IP_ADDRESSES = Array(
        "Stanford Wifi"                 => "/10\.39\./",
        "Stanford LAN"                  => "/^171\.65\./",
        "cci-webapp-securerc-02"        => "/172\.25\.104\.84/",
        "cci-webapp-devrc-02"           => "/172\.25\.104\.89/",
        "cci-webapp-devrc-03"           => "/172\.25\.104\.92/",
        "gcp stuff"                     => "/104\.198\.1/",
        "timecard app"                  => "/35.185.219.88/"
);


$AUTHORIZED_TOKENS = Array(
	"REDCAP_TOKEN"	=> "0dWhFQtgZN7VkCnDyzsoyZFoZGqKE4oALWMgs2K6JBkRZWS1dN",
	"EXCEL_TOKEN" 	=> "LqjcQQei95e2tLjgQZr7KnHcCejJTLea",
	"AMIE"		=> "pXJ5xNwj1PZQPowo8L2vGuxqlWaca1C2",
	"REDCAP_DET"	=> "pXJ5xNwj1P");

$userid = 	isset($_REQUEST['userid'])	? $_REQUEST['userid'] : "";
$only =  	isset($_REQUEST['only']) 	? $_REQUEST['only'] 	: "uid,mail,sudisplaynamelast,sudisplaynamefirst,ou,suaffiliation,sugwaffiliation1,telephonenumber";
$token = 	isset($_REQUEST['token']) 	? $_REQUEST['token'] 	: "NOT SET";
$exact =	isset($_REQUEST['exact'])	? strtolower($_REQUEST['exact'])	: "";
$nocache =  isset($_REQUEST['nocache']) ? true : false;

//this should only be called from an authorized server.

if (!validateIP($AUTHORIZED_IP_ADDRESSES)) {
	$error = "Request coming from unauthorized ip address.\t".$_SERVER['QUERY_STRING'];
	returnError($error);
}

//validate token (a second precaution)
$validatedAs="";
foreach ($AUTHORIZED_TOKENS as $a => $t) {
	if ($token == $t) {
		$validatedAs=$a;
		break;
	}
}
if ($validatedAs == "") {
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
}


$source = "";
$md5 = md5($userid . $only);
$cacheFile = "/tmp/LDAP-$md5";
if (file_exists($cacheFile)) {
	$cache = file_get_contents("/tmp/LDAP-$md5");
} else {
	$cache = false;
}

if ($cache && !$nocache) {
	$output = $cache;
	$source = "cache";
} else {
	if ( !isset( $ldap ) ) $ldap = new LDAP();
	//echo "filter: $filter, only: $only<hr>";

	$results = Array();
	$rs = $ldap->query($filter, explode(",",$only));
	//$rs = $ldap->query($filter);	//returns everything from LDAP
	if ( $rs ) {
		$numRows = $ldap->getNumRows($rs);
		$results['count'] = $numRows;
	//	$i=1;
		if ($numRows == 1) {
			$row=$ldap->getRow($rs);
			foreach($row as $k => $v) {
				//skip numberic keys
				if (! is_numeric($k)) {
					//concatenate array values
					if (is_array($v)) {
						$results[$k] = implode(" | ",$v);
					} else {
						$results[$k] = $v;
					}
				}
			}
		} else {
			$results['error'] = "Found $numRows matches.";
		}
	}
	$output = json_encode($results);
	//file_put_contents("/tmp/LDAP-$md5", $output);
	file_put_contents("/var/log/webtools/ldap-cache/LDAP-$md5", $output);
	$source = "ldap";
}

echo $output;

logSuccess($output."\t".$source);

function logSuccess($msg) {
	//log to text file
	file_put_contents( LOG_PATH . date( 'Y-m-d-' ) . LOG_PREFIX . '-success.log',
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
			$returnArray = Array("error" => "Please notify informaticsconsultation@lists.stanford.edu of an error in ldap_lookup.php");
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
	$result = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : voefs('REMOTE_ADDR');
	$result = implode(", ",array_unique(explode(", ",$result)));	//filter out duplicates
	return $result;
}

?>