<?php
/**
 * This is meant to translate our existing ldap queries into the new format supported by the REDCap External
 * Module Username Validator.
 *
 * Basically, it has to return just an array of 'status' and 'message'
 *
 * So, I'm moving the code that used to be in REDCap to this file which will reside on webtools.
 *
 */

require_once("secure/LDAP.php");
require_once (__DIR__ ."/../../vendor/autoload.php");
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();
define('LOG_PATH', "/var/log/webtools/");
define('LOG_PREFIX', "redcap_lookup");
define('DEBUG', "false");
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


//DEBUG
//ECHO '{"count":1,"1":{"uid":"andy123","sudisplaynamefirst":"Andrew","sudisplaynamelast":"Martin","mail":"andy123@stanford.edu"}}';
//exit;

$REDCAP_AUTHORIZED_IP_ADDRESSES = Array(
    //	"cci-webapp-devrc-02" =>    "/172\.25\.104\.40/",
    //	"cci-webapp-securerc-02" => "/172\.25\.104\.84/",
    //	"cci-webapp-devrc-03" =>    "/172\.25\.104\.92/",
    "temp" =>		"/.*/"
);



//This is a unique token that is embedded in the profile module as an added precaution

$username = isset($_REQUEST['username'])	? $_REQUEST['username']             : "";
$only   =  	isset($_REQUEST['only']) 	    ? $_REQUEST['only'] 	            : "uid,mail,displayname,sudisplaynamelast,sudisplaynamefirst";		//default to uid return only
$token  = 	isset($_REQUEST['token']) 	    ? $_REQUEST['token'] 	            : "";
$exact  =	isset($_REQUEST['exact'])	    ? filter_var($_REQUEST['exact'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) : "FALSE";


// This should only be called from the actual redcap server.
if (!validateIP($REDCAP_AUTHORIZED_IP_ADDRESSES)) {
    $error = "Request coming from unauthorized ip address.\t".$_SERVER['QUERY_STRING'];
    returnError($error);
}

// Validate token (a second precaution)
if ($_ENV['REDCAP_TOKEN'] != $token) {
    $error = "Invalid token: $token in\t".$_SERVER['QUERY_STRING'];
    returnError($error);
}

// Make sure we have a valid username
if ($username == "") {
    $error = "Missing userid for REDCap query in \t".$_SERVER['QUERY_STRING'];
    returnError($error);
}

// Set filters
if ($exact) {
    $l = strtolower($username);
    $filter="(|(uid=$username)(suSunetId=$username)(uid=$l)(suSunetId=$l))";
} else {
    //in cases where people use an alias as email (andy.b.martin@stanford.edu, we need to strip the @stanford.edu for the match to work)
    $userid_stripped = preg_replace('/([^@]*)@(.*stanford.edu)/i','${1}',$username);
    $l = strtolower($userid_stripped);
    $filter="(|(uid=$userid_stripped)(susunetid=$userid_stripped)(mail=$userid_stripped@stanford.edu)(mail=$userid_stripped)(uid=$l)(susunetid=$l)(mail=$l@stanford.edu)(mail=$l))";
    //search by sunet or mail
    //$filter="(|(uid=$userid)(susunetid=$userid)(mail=$userid@stanford.edu)(mail=$userid))";	//search by sunet or mail
}
//echo "filter: $filter, only: $only<hr>";

#### END OF SECURITY MEASURES ####


## For stanfordhealthcare.org or
// stanfordhealthcare.org
// stanfordchildrens.org

if (preg_match('/.*@(stanfordhealthcare\.org|stanfordchildrens\.org)$/', $username, $matches)) {
    $result['status'] = true;
    $result['user'] = [
        "username" => strtolower($username),
        "user_email" => strtolower($username)
    ];
    $result['message'] = "The username verification service does not currently work for non-SUNET based accounts.  You may continue without user verification but please double-check that the username entered is correct.<br>";
    header('Content-Type: application/json');
    echo json_encode($result);
    exit;
}



## DO THE LDAP LOOKUP

// Create the LDAP Object
if ( !isset( $ldap ) ) $ldap = new LDAP();

// Make an array to hold results from ldap
$results = Array();
$fieldsArray = explode(",", $only);
// Do the query and add to results
$rs = $ldap->query($filter);
if ( $rs ) {
    $numRows = $ldap->getNumRows($rs);
    $i=1;
    while ($row=$ldap->getRow($rs)) {
        if ( isset ($row['uid'] ) || isset ($row['susunetid']) ) {
             $arrResult = Array();
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

// Results contains an array as
// {"count":1,"1":{"username":"scweber","user_displayname":"Susan C Weber","user_firstname":"Susan","user_lastname":"Weber","user_email":"scweber@stanford.edu"}}
logDebug(json_encode($results));
$ldap_result = $results;



## PROCESS THE RESULT
$result = array();
$msg = array();	// Array to hold messages
$status = FALSE;


// If the LDAP server is down or another error occurs, notify the user
if (empty($ldap_result)) {
    // Deliver error message and exit
    $status = false;
    $msg[] = "There was an error validating the specified SUNet ID (<b>$username</b>).<br/><br/> ".
            "This usually means the Stanford LDAP resource is not responding or another network error ".
            "has occurred.  Please back up and try again.  If this error recurs, please send an email to ".
            "<a href='mailto:redcap-help@lists.stanford.edu'>redcap-help@lists.stanford.edu</a> ".
            "describing the problem. ".
            "<hr><br>We apologize for the inconvenience and will do our best to resolve it promptly.";
    // Potentially notify a REDCap admin! with $ldap_result as a message
} else {

    // Process results
    $count = $ldap_result['count'];
    if ($count === 0) {
        // No match found
        $status = false;
        $msg[] = "The specified SUNet ID, <b><u>$username</u></b>, does not appear to be valid.<br/><br/> ".
            "Many users have email aliases (e.g. Jane.Doe@stanford.edu) where the email prefix is not " .
            "the same as their SUNet ID.  A SUNet ID should be 8 characters or less without any periods " .
            "or hyphens.<br/><br/>Try searching the " .
            "<a href='https://stanford.rimeto.io/search/$username' target='_BLANK'> ".
            "<div class='btn btn-xs btn-danger'><b>Stanford Directory</b></div></a> or contact your collaborator to obtain their SUNet ID.";
        logDebug("$username returned count 0");
    } else {
        // Look for an exact match in the remaining 1 or more ldap results
        $match_index = 0;
        for ($i = 1; $i <= $count; $i++) {
            if (strtolower($ldap_result[$i]['username']) == strtolower($username)) {
                $match_index = $i;
                break;
            }
        }

        if ($match_index) {
            // An exact match was found
            $status = TRUE;

            // Return matching user
            $result['user'] = $ldap_result[$i];

            // If there were additional 'partial' matches, return them beneath the exact match so user is posititve
            // they are selecting the right person
            if ($count > 1) {
                $other_results = $ldap_result;
                unset($other_results[$match_index]);    // Remove the match so it doesn't appear in the table

                $msg[] = "In addition to the exact match, the following accounts were also returned from your search. ".
                    "If you were trying to add one of these user(s) to your project, please cancel and try again ".
                    "using the exact SUNet ID for the user.<br><br>" . get_table_from_ldap_results($other_results);
            }
        } else {
            // No exact match was found, but partial match(es) were.  Display a list of those matches
            $status = FALSE;
            $msg[] = "The username you specified (<b>$username</b>) is a potential match for the following ".
                "accounts:<br><br>" . get_table_from_ldap_results($ldap_result) . "<br><br>Please use the exact ".
                "<u>SUNetID</u> for the user you are looking for and try again.<br><br>If none of these are the ".
                "user you are looking for, please use <a href='https://stanford.rimeto.io/search/$username' ".
                "target='_BLANK'>Stanford Directory</a> to locate your collaborator.";
        }
    }
}

$result['status'] = $status;
$result['message'] = implode('<br><br>',$msg);

header('Content-Type: application/json');
echo json_encode($result);



### SUPPORT FUNCTIONS

// Formulates a nice html table from the ldap results
function get_table_from_ldap_results ($ldap_result) {
    $c = "<table style='margin:0px 20px;'><tr>
        <th style='padding: 0px 10px;'><b>SUNetID</b></th>
        <th style='padding: 0px 10px;'><b>Name</b></th>
        <th style='padding: 0px 10px;'><b>Email</b></th></tr>";
        for ($i=1;$i <= $ldap_result['count'];$i++) {
            $c .= "<tr>";
            $c .= "<td style='padding: 3px 10px;'><b>" . $ldap_result[$i]['username'] . "</b></td>";
            $c .= "<td style='padding: 3px 10px;'>" . $ldap_result[$i]['user_firstname'] .
                    " " . $ldap_result[$i]['user_lastname'] . "</td>";
            $c .= "<td style='padding: 3px 10px;'>" . $ldap_result[$i]['user_email'] . "</td>";
            $c .= "</tr>";
        }
        $c .= "</table>";
        return $c;
}


function logSuccess($msg) {
    //log to text file
    file_put_contents( LOG_PATH . date( 'Y-m-' ) . LOG_PREFIX . '-success.log',
        date( 'Y-m-d H:i:s' ) . "\t" . getIP() . "\t" . $_SERVER['QUERY_STRING'] . "\t" . $msg . "\n", FILE_APPEND );
}


function logDebug($msg) {
    //log to text file
    file_put_contents( LOG_PATH . date( 'Y-m-' ) . LOG_PREFIX . '-debug.log',
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

function getIP() {
    $result = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
    $result = implode(", ",array_unique(explode(", ",$result)));	//filter out duplicates
    return $result;
}

function array_unshift_assoc(&$arr, $key, $val) {
    $arr = array_reverse($arr, true);
    $arr[$key] = $val;
    $arr = array_reverse($arr, true);
}

