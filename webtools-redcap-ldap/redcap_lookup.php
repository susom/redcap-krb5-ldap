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

define('LOG_PATH', "/var/log/webtools/");
define('LOG_PREFIX', "redcap_lookup");
define('DEBUG', "false");

//DEBUG
//ECHO '{"count":1,"1":{"uid":"andy123","sudisplaynamefirst":"Andrew","sudisplaynamelast":"Martin","mail":"andy123@stanford.edu"}}';
//exit;

/* Old Authorized Addresses

"Todd's Server" =>          "/171\.65\.57\.11/",
"Stanford Wifi" =>          "/10\.39\./",
"Stanford LAN"  =>          "/^171\.65\./",

*/

$REDCAP_AUTHORIZED_IP_ADDRESSES = array(
    "cci-webapp-devrc-02" => "/172\.25\.104\.40/",
    "cci-webapp-securerc-02" => "/172\.25\.104\.84/",
    "cci-webapp-devrc-03" => "/172\.25\.104\.92/",
    "temp" => "/.*/"
);

//This is a unique token that is embedded in the profile module as an added precaution
define('REDCAP_TOKEN', "0dWhFQtgZN7VkCnDyzsoyZFoZGqKE4oALWMgs2K6JBkRZWS1dN");

$userid = isset($_REQUEST['userid']) ? $_REQUEST['userid'] : "";
$only = isset($_REQUEST['only']) ? $_REQUEST['only'] : "uid,mail,displayname,sudisplaynamelast,sudisplaynamefirst";        //default to uid return only
$token = isset($_REQUEST['token']) ? $_REQUEST['token'] : "";
$exact = isset($_REQUEST['exact']) ? strtolower($_REQUEST['exact']) : "";

//this should only be called from the actual redcap server.

if (!validateIP($REDCAP_AUTHORIZED_IP_ADDRESSES)) {
    $error = "Request coming from unauthorized ip address.\t" . $_SERVER['QUERY_STRING'];
    returnError($error);
}

//validate token (a second precaution)
if (REDCAP_TOKEN != $token) {
    $error = "Invalid token: $token in\t" . $_SERVER['QUERY_STRING'];
    returnError($error);
}

if ($userid == "") {
    $error = "Missing userid for REDCap query in \t" . $_SERVER['QUERY_STRING'];
    returnError($error);
}
if ($exact == "true") {
    $filter = "uid=$userid";
} else {
    //in cases where people use an alias as email (andy.b.martin@stanford.edu, we need to strip the @stanford.edu for the match to work)
    $userid_stripped = preg_replace('/([^@]*)@(.*stanford.edu)/i', '${1}', $userid);
    $filter = "(|(uid=$userid_stripped)(susunetid=$userid_stripped)(mail=$userid_stripped@stanford.edu)(mail=$userid_stripped))";    //search by sunet or mail
    //$filter="(|(uid=$userid)(susunetid=$userid)(mail=$userid@stanford.edu)(mail=$userid))";	//search by sunet or mail
}
if (!isset($ldap)) $ldap = new LDAP();

//echo "filter: $filter, only: $only<hr>";

$results = array();
//$rs = $ldap->query($filter, explode(",",$only));
$fieldsArray = explode(",", $only);
$rs = $ldap->query($filter);
if ($rs) {
    $numRows = $ldap->getNumRows($rs);
    $i = 1;
    while ($row = $ldap->getRow($rs)) {
        if (isset ($row['uid'])) {
            $arrResult = array();
            $arrResult['uid'] = $row['uid'];
            $arrResult['username'] = empty($row['uid']) ? $row['susunetid'] : $row['uid'];
            if (in_array('displayname', $fieldsArray) && isset( $row['displayname'] )) 		    $arrResult['user_displayname']  = $row['displayname'];
            if (in_array('sudisplaynamefirst', $fieldsArray) && isset( $row['sudisplaynamefirst'] )) 	$arrResult['user_firstname']    = $row['sudisplaynamefirst'];
            if (in_array('sudisplaynamelast', $fieldsArray) && isset( $row['sudisplaynamelast'] )) 	$arrResult['user_lastname']     = $row['sudisplaynamelast'];
            if (in_array('mail', $fieldsArray) && isset( $row['mail'] )) 			        $arrResult['user_email']        = $row['mail'];
            if (in_array('suaffiliation', $fieldsArray) && isset( $row['suaffiliation'] )) 			        $arrResult['suaffiliation']        = $row['suaffiliation'];
            if (in_array('sugwaffiliation1', $fieldsArray) && isset( $row['sugwaffiliation1'] )) 			        $arrResult['sugwaffiliation1']        = $row['sugwaffiliation1'];
            if (in_array('sudisplaynamelf', $fieldsArray) && isset( $row['sudisplaynamelf'] )) 			        $arrResult['sudisplaynamelf']        = $row['sudisplaynamelf'];
            if (in_array('telephonenumber', $fieldsArray) && isset( $row['telephonenumber'] )) 			        $arrResult['telephonenumber']        = $row['telephonenumber'];
            if (in_array('suprimaryorganizationid', $fieldsArray) && isset( $row['suprimaryorganizationid'] )) 			        $arrResult['suprimaryorganizationid']        = $row['suprimaryorganizationid'];
            if (in_array('ou', $fieldsArray) && isset( $row['ou'] )) 			        $arrResult['ou']        = $row['ou'];
            if (in_array('susunetid', $fieldsArray) && isset( $row['susunetid'] )) 			        $arrResult['susunetid']        = $row['susunetid'];
            if (in_array('suprimaryorganizationid', $fieldsArray) && isset( $row['suprimaryorganizationid'] )) 			        $arrResult['suprimaryorganizationid']        = $row['suprimaryorganizationid'];
            if (in_array('suregisterednamelf', $fieldsArray) && isset( $row['suregisterednamelf'] )) 			        $arrResult['suregisterednamelf']        = $row['suregisterednamelf'];

            $results[$i] = $arrResult;
            $i++;
        }
    }
    array_unshift_assoc($results, 'count', count($results));
}

$output = json_encode($results);

echo $output;

logSuccess($output);

function logSuccess($msg)
{
    //log to text file
    file_put_contents(LOG_PATH . date('Y-m-') . LOG_PREFIX . '-success.log',
        date('Y-m-d H:i:s') . "\t" . getIP() . "\t" . $_SERVER['QUERY_STRING'] . "\t" . $msg . "\n", FILE_APPEND);
}

function returnError($error)
{
    $errorMsg = $error;

    //log to text file
    file_put_contents(LOG_PATH . date('Y-m-d-') . LOG_PREFIX . '-errors.log',
        date('Y-m-d H:i:s') . "\t" . getIP() . "\t" . $errorMsg . "\n", FILE_APPEND);

    //Return error to screen
    if (DEBUG == "true") {
        $returnArray = array("error" => $errorMsg);
    } else {
        $returnArray = array("error" => "Please notify redcap-help@lists.stanford.edu of an error in redcap_lookup.php");
    }
    echo(json_encode($returnArray));
    exit;
}

function validateIP($allowedIPs)
{
    // validate source IP
    $IPallowed = false;
    $currentIP = getIP();
    foreach ($allowedIPs as $label => $ip) {
        if (preg_match($ip, $currentIP)) {
            $IPallowed = true;
            break;
        }
    }
    return $IPallowed;
}

// Get the calling IP address
function getIP()
{
    $result = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
    $result = implode(", ", array_unique(explode(", ", $result)));    //filter out duplicates
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