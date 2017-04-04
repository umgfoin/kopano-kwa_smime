<?php

include_once('lib/X509.php');
include_once('lib/Ocsp.php');

function tempErrorHandler($errno, $errstr, $errfile, $errline) {
	return true;
}

class Certificate
{
	private $cert;
	private $data;

	function __construct($cert, $issuer = '') {
		// XXX: error handling
		$this->data = openssl_x509_parse($cert);
		$this->cert = $cert;
		$this->issuer = $issuer;
	}

	/**
	 * Converts X509 DER format string to PEM format
	 *
	 * @param {string} X509 Certificate in DER format
	 * @return {string} X509 Certificate in PEM format
	 */
	protected function der2pem($cert)
	{
		return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($cert),64,"\n") . "-----END CERTIFICATE-----\n";
	}

	/**
	 * Converts X509 PEM format string to DER format
	 *
	 * @param {string} X509 Certificate in PEM format
	 * @return {string} X509 Certificate in DER format
	 */
	protected function pem2der($pem_data)
	{
		$begin = "CERTIFICATE-----";
		$end   = "-----END";
		$pem_data = substr($pem_data, strpos($pem_data, $begin)+strlen($begin));    
		$pem_data = substr($pem_data, 0, strpos($pem_data, $end));
		return base64_decode($pem_data);
	}

	/**
	 * The subject/emailAddress or subjectAltName
	 * @return string The email address belonging to the certificate
	 */
	function emailAddress() {
		$certEmailAddress = "";
		// If subject/emailAddress is not set, try subjectAltName
		if(isset($this->data['subject']['emailAddress'])) {
			$certEmailAddress = $this->data['subject']['emailAddress'];
		} else if(isset($this->data['extensions']) && 
			isset($this->data['extensions']['subjectAltName'])) { 
			// Example [subjectAltName] => email:foo@bar.com
			$tmp = explode('email:', $this->data['extensions']['subjectAltName']);
			// Only get the first match
			if(isset($tmp[1]) && !empty($tmp[1])) {
				$certEmailAddress = $tmp[1];
			}
		}
		return $certEmailAddress;
	}

	/**
	 * Return the certificate in DER format.
	 *
	 * @return string certificate in DER format 
	 */
	function der() {
		return $this->pem2der($this->cert);	
	}

	/**
	 * Return the certificate in PEM format
	 *
	 * @return string certificate in PEM format 
	 */
	function pem() {
		return $this->cert;
	}

	/**
	 * The beginning of the valid period of the certificate.
	 *
	 * @return integer timestamp from which the certificate is valid
	 */
	function validFrom() {
		return $this->data['validFrom_time_t'];
	}

	/**
	 * The end of the valid period of the certificate
	 *
	 * @return integer timestamp from which the certificate is invalid
	 */
	function validTo() {
		return $this->data['validTo_time_t'];
	}

	/**
	 * Determines if the certificate is valid
	 *
	 * @return boolean the valid status
	 */
	function valid() {
		$time = time();
		return $time > $this->validFrom() && $time < $this->validTo();
	}

	/**
	 * The caURL of the certififcate
	 *
	 * @return string return an empty string or the CA URL.
	 */
	function caURL() {
		$authorityInfoAccess = $this->authorityInfoAccess();
		if (preg_match("/CA Issuers - URI:(.*)/", $authorityInfoAccess, $matches)) {
			return array_pop($matches);
		}

		return '';
	}

	/**
	 * The OCSP URL of the certificate
	 *
	 * @return string return an empty string or the OCSP URL.
	 */
	function ocspURL() {
		$authorityInfoAccess = $this->authorityInfoAccess();
		if (preg_match("/OCSP - URI:(.*)/", $authorityInfoAccess, $matches)) {
			return array_pop($matches);
		}

		return '';
	}

	/**
	 * Internal helper to obtain the authorityInfoAccess information.
	 *
	 * @return string authorityInfoAccess if set.
	 */
	protected function authorityInfoAccess() {
		if (!isset($this->data['extensions'])) {
			return '';
		}

		if (!isset($this->data['extensions']['authorityInfoAccess'])) {
			return '';
		}
		
		return $this->data['extensions']['authorityInfoAccess'];
	}

	/**
	 * The fingerprint (hash) of the certificate body.
	 *
	 * @param string hash_algorithm either sha1 or md5.
	 * @return string the hash of the certificate's body
	 */
	public function fingerprint($hash_algorithm = "md5") {
		$body = str_replace('-----BEGIN CERTIFICATE-----', '', $this->cert);
		$body = str_replace('-----END CERTIFICATE-----', '', $body);
		$body = base64_decode($body);
		if ($hash_algorithm === 'sha1') {
			$fingerprint = sha1($body);
		} else {
			$fingerprint = md5($body);
		}
		// Format 1000AB as 10:00:AB
		return strtoupper(implode(':', str_split($fingerprint, 2)));
	}

	/**
	 * The issuer of this certificate
	 *
	 * @return Certificate the issuer certificate
	 */
	function issuer() {
		if (!empty($this->issuer)) {
			return new Certificate($this-issuer);
		} else {
			$cert = '';
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $this->caURL());
			curl_setopt($ch, CURLOPT_FAILONERROR, true);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			$output = curl_exec($ch);
			$http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			if (!curl_error($ch) && $http_status === 200) {
				$cert = $this->der2pem($output);
			}
			curl_close($ch);

			return new Certificate($cert);
		}
	}

	/**
	 * Verify the certificate status using OCSP
	 *
	 * @return boolean verification succeeded or failed
	 */
	function verify() {
		$message = [];

		if (!$this->valid()) {
			return false;
		}

		$issuer = $this->issuer();
		if (!is_object($issuer)) {
			return false;
		}

		/* Set custom error handler since the nemid ocsp library uses
		 * trigger_error() to throw errors when it cannot parse certain
		 * x509 fields which are not required for the OCSP Reuqest.
		 * Also when receiving the OCSP request, the OCSP library
		 * triggers errors when the request does not adhere to the
		 * standard.
		 */
		set_error_handler("tempErrorHandler");

		$x509 = new \WAYF\X509();
		$issuer = $x509->certificate($issuer->der());
		$certificate = $x509->certificate($this->der());

		$ocspclient = new \WAYF\OCSP();
		$certID = $ocspclient->certOcspID(array(
		    'issuerName' => $issuer['tbsCertificate']['subject_der'],
		    // remember to skip the first byte it is the number of
		    // unused bits and it is always 0 for keys and certificates
		    'issuerKey' => substr($issuer['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'], 1),
		    'serialNumber_der' => $certificate['tbsCertificate']['serialNumber_der']
	    	),
		'sha1');

		$ocspreq = $ocspclient->request(array($certID));

		$stream_options = array(
		    'http' => array(
			'ignore_errors' => false,
			'method' => 'POST',
			'header' => 'Content-type: application/ocsp-request' . "\r\n",
			'content' => $ocspreq,
			'timeout' => 1,
		    ),
		);

		// Do the OCSP request
		$context = stream_context_create($stream_options);
		$derresponse = file_get_contents($this->ocspURL(), null, $context);
		// OCSP service not avaliable, import certificate, but show a warning.
		if ($derresponse === false) {
			return true;
		}
		$ocspresponse = $ocspclient->response($derresponse);

		// Restore the previous error handler
		restore_error_handler();

		if (isset($ocspresponse['responseStatus']) &&
			$ocspresponse['responseStatus'] !== 'successful') {
			// Certificate status is not good, revoked or unknown
			return false;
		}

		$resp = $ocspresponse['responseBytes']['BasicOCSPResponse']['tbsResponseData']['responses'][0];
		/* 
		 * OCSP response status, possible values are: good, revoked,
		 * unknown according to the RFC
		 * https://www.ietf.org/rfc/rfc2560.txt
		 */
		if($resp['certStatus'] !== 'good') {
			// Certificate status is not good, revoked or unknown
			return false;
		}

		/* Check if:
		 * - hash algorithm is equal
		 * - check if issuerNamehash is the same from response
		 * - check if issuerKeyHash is the same from response
		 * - check if serialNumber is the same from response
		 */
		if($resp['certID']['hashAlgorithm'] !== 'sha1'
			&& $resp['certID']['issuerNameHash'] !== $certID['issuerNameHash']
			&& $resp['certID']['issuerKeyHash'] !== $certID['issuerKeyHash']
			&& $resp['certID']['serialNumber'] !== $certID['serialNumber']) {
			// OCSP Revocation, mismatch between original and checked certificate
			return false;
		}

		// check if OCSP revocation update is recent
		$now = new DateTime(gmdate('YmdHis\Z'));
		$thisUpdate = new DateTime($resp['thisUpdate']);

		// Check if update time is earlier then our own time
		if (!isset($resp['nextupdate']) && $thisUpdate > $now) {
			return false;
		}

		// Current time should be between thisUpdate and nextUpdate.
		if ($thisUpdate > $now && $now > new Datetime($resp['nextUpdate'])) {
			// OCSP Revocation status not current
			return false;
		}

		return true;
	}
}
