<?php
/**
 * This file contains functions which are used in plugin.smime.php and class.pluginsmimemodule.php and therefore
 * exists here to avoid code-duplication
 */

/**
 * Function which extracts the email address from a certificate, and tries to get the subjectAltName if
 * subject/emailAddress is not set.
 *
 * @param {Mixed} $certificate certificate data
 */
function getCertEmail($certificate)
{
	$certEmailAddress = "";
	// If subject/emailAddress is not set, try subjectAltName
	if(isset($certificate['subject']['emailAddress'])) {
		$certEmailAddress = $certificate['subject']['emailAddress'];
	} else if(isset($certificate['extensions']) && isset($certificate['extensions']['subjectAltName'])) { 
		// Example [subjectAltName] => email:foo@bar.com
		$tmp = explode('email:', $certificate['extensions']['subjectAltName']);
		// Only get the first match
		if(isset($tmp[1]) && !empty($tmp[1])) {
			$certEmailAddress = $tmp[1];
		}
	}
	return $certEmailAddress;
}

/**
 * Function that will return the private certificate of the user from the user store where it is stored in pkcs#12 format
 * @param {MAPIStore} $store user's store
 * @param {String} $type of message_class.
 * @param {String} $emailAddress emailaddress to specify.
 * @return {MAPIObject} the mapi message containing the private certificate, returns false if no certifcate is found
 *
 * FIXME: in the future we might support multiple private certs
 */
function getMAPICert($store, $type = 'WebApp.Security.Private', $emailAddress = '')
{
	$root = mapi_msgstore_openentry($store, null);
	$table = mapi_folder_getcontentstable($root, MAPI_ASSOCIATED);

	$restrict = array(RES_PROPERTY,
		array( 
			RELOP => RELOP_EQ,
			ULPROPTAG => PR_MESSAGE_CLASS,
			VALUE => array(PR_MESSAGE_CLASS => $type)
		)
	);
	if($type == 'WebApp.Security.Public' && !empty($emailAddress)) {
		$restrict = array(RES_AND, array(
			$restrict,
			array(RES_CONTENT,
				array(
					FUZZYLEVEL => FL_FULLSTRING | FL_IGNORECASE,
					ULPROPTAG => PR_SUBJECT,
					VALUE => array(PR_SUBJECT => $emailAddress)
				),
			)
		));
	}


	// PR_MESSAGE_DELIVERY_TIME validTo / PR_CLIENT_SUBMIT_TIME validFrom
	mapi_table_restrict($table, $restrict, TBL_BATCH);
	mapi_table_sort($table, array(PR_MESSAGE_DELIVERY_TIME => TABLE_SORT_DESCEND), TBL_BATCH);

	$privateCerts = mapi_table_queryallrows($table, array(PR_ENTRYID, PR_SUBJECT, PR_MESSAGE_DELIVERY_TIME, PR_CLIENT_SUBMIT_TIME), $restrict);


	if(!empty($privateCerts)) {
		// FIXME: more error checking?
		return $privateCerts[0];
	}
	return false;
}

/**
 * Function that will decrypt the private certificate using a supplied password
 *
 * @param {MAPIStore} $store user's store
 * @param {String} $passphrase passphrase for private certificate
 * @return {Mixed} collection of certificates, empty if none if decrypting fails or stored private certificate isn't found
 *
 * FIXME: in the future we might support multiple private certs
 */
function readPrivateCert($store, $passphrase)
{
	$certs = array();
	$pkcs12 = "";
	$privateCert = getMAPICert($store);
	$privateCertMessage = mapi_msgstore_openentry($store, $privateCert[PR_ENTRYID]);

	if($privateCertMessage !== false) {
		$stream = mapi_openproperty($privateCertMessage, PR_BODY, IID_IStream, 0, 0);
		$stat = mapi_stream_stat($stream);
		mapi_stream_seek($stream, 0, STREAM_SEEK_SET);
		for ($i = 0; $i < $stat['cb']; $i += 1024) {
			$pkcs12 .= mapi_stream_read($stream,1024);
		}
		openssl_pkcs12_read(base64_decode($pkcs12), $certs, $passphrase);
	}

	return $certs;
}

/**
 * Converts X509 DER format string to PEM format
 *
 * @param {string} X509 Certificate in DER format
 * @return {string} X509 Certificate in PEM format
 */
function der2pem($certificate) {
	return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($certificate),64,"\n") . "-----END CERTIFICATE-----\n";
}

/**
 * Converts X509 PEM format string to DER format
 *
 * @param {string} X509 Certificate in PEM format
 * @return {string} X509 Certificate in DER format
 */
function pem2der($pem_data)
{
	$begin = "CERTIFICATE-----";
	$end   = "-----END";
	$pem_data = substr($pem_data, strpos($pem_data, $begin)+strlen($begin));    
	$pem_data = substr($pem_data, 0, strpos($pem_data, $end));
	return base64_decode($pem_data);
}

/**
 * Detect if the encryptionstore has a third parameter which sets the expiration.
 * Remove when WebApp 3.4.0 is removed.
 * @return {boolean} true is expiration is supported
 */
function encryptionStoreExpirationSupport() {
	$refClass = new ReflectionClass('EncryptionStore');
	return count($refClass->getMethod('add')->getParameters()) === 3;
}

/**
 * Open PHP session if it not open closed. Returns if the session was opened.
 */
function withPHPSession($func, $sessionOpened = false) {
	if (session_status() === PHP_SESSION_NONE) {
		session_start();
		$sessionOpened = true;
	}

	$func();

	if ($sessionOpened) {
		session_write_close();
	}
}
?>
