<?php
include_once('util.php');
include_once('lib/X509.php');
include_once('lib/Ocsp.php');

// Green, everything was good
define('SMIME_STATUS_SUCCESS', 0);
// Orange, CA is missing or OCSP is not avaliable
define('SMIME_STATUS_PARTIAL', 1);
// Red, something really went wrong
define('SMIME_STATUS_FAIL', 2);

define('SMIME_SUCCESS', 0);
define('SMIME_NOPUB', 1);
define('SMIME_CERT_EXPIRED', 2);
define('SMIME_ERROR', 3);
define('SMIME_REVOKED', 4);
define('SMIME_CA', 5);
define('SMIME_DECRYPT_SUCCESS', 6);
define('SMIME_DECRYPT_FAILURE', 7);
define('SMIME_UNLOCK_CERT', 8);
define('SMIME_OCSP_NOSUPPORT', 9);
define('SMIME_OCSP_DISABLED', 10);
define('SMIME_OCSP_FAILED', 11);

// OpenSSL Error Constants
// openssl_error_string() returns error codes when an operation fails, since we return custom error strings 
// in our plugin we keep a list of openssl error codes in these defines
define('OPENSSL_CA_VERIFY_FAIL', '21075075');

class Pluginsmime extends Plugin {

	/**
	 * decrypted/verified message
	 */
	private $messsage = array();

	/**
	 * Called to initialize the plugin and register for hooks.
	 */
	function init(){
		$this->registerHook('server.core.settings.init.before');
		$this->registerHook('server.util.parse_smime.signed');
		$this->registerHook('server.util.parse_smime.encrypted');
		$this->registerHook('server.module.itemmodule.open.after');
		$this->registerHook('server.core.operations.submitmessage');
		$this->registerHook('server.upload_attachment.upload');
		$this->registerHook('server.module.createmailitemmodule.beforesend');
		$this->store = $GLOBALS['mapisession']->getDefaultMessageStore();

		if(version_compare(phpversion(), '5.4', '<')) {
			$this->cipher = OPENSSL_CIPHER_3DES;
		} else {
			$this->cipher = PLUGIN_SMIME_CIPHER;
		}

	}

	/**
	 * Process the incoming events that where fired by the client.
	 *
	 * @param String $eventID Identifier of the hook
	 * @param Array $data Reference to the data of the triggered hook
	 */
	function execute($eventID, &$data) {
		switch($eventID){
			// Register plugin
			case 'server.core.settings.init.before':
				$this->onBeforeSettingsInit($data);
				break;
			// Verify a signed or encrypted message when an email is opend
			case 'server.util.parse_smime.signed':
				$this->onSignedMessage($data);
				break;
			case 'server.util.parse_smime.encrypted':
				$this->onEncrypted($data);
				break;
			// Add S/MIME property, which is send to the client
			case 'server.module.itemmodule.open.after':
				$this->onAfterOpen($data);
				break;
			// Catch uploaded certificate
			case 'server.upload_attachment.upload':
				$this->onUploadCertificate($data);
				break;
			// Sign email before sending
			case 'server.core.operations.submitmessage':
				$this->onBeforeSend($data);
				break;
			// Verify that we have public certificates for all recipients
			case 'server.module.createmailitemmodule.beforesend':
				$this->onCertificateCheck($data);
				break;
		}
	}

	/**
	 * Function checks if public certificate exists for all recipients.
	 * TODO: we do not check the GAB for X509 certs.
	 * 
	 * @param Array $data Reference to the data of the triggered hook
	 */
	function onCertificateCheck($data) {
		$entryid = $data['entryid'];
		// FIXME: unittests, save trigger will pass $entryid is 0 (which will open the root folder and not the message we want)
		if($entryid !== false) {
			$message = mapi_msgstore_openentry($this->store, $entryid);
			$module = $data['moduleObject'];
			$data['success'] = true;

			$messageClass = mapi_getprops($message, array(PR_MESSAGE_CLASS));
			$messageClass = $messageClass[PR_MESSAGE_CLASS];
			if($messageClass === 'IPM.Note.SMIME' || $messageClass === 'IPM.Note.SMIME.SignedEncrypt') {
				$recipients = $data['action']['props']['smime'];

				$missingCerts = Array();
				foreach($recipients as $emailAddr) {
					if(!$this->pubcertExists(($emailAddr))) {
						array_push($missingCerts, $emailAddr);
					}
				}
				if(!empty($missingCerts)) {
					$module = $data['moduleObject'];
					$errorMsg = _('Missing public certificates for the following recipients: ') . implode(', ', $missingCerts) . _('. Please contact your system administrator for details', 'plugin_smime');
					$module->sendFeedback(false, array("type" => ERROR_GENERAL, "info" => array('display_message' => $errorMsg )));
					$data['success'] = false;
				}
			}
		}
	}

	/**
	 * Function which verifies a message
	 *
	 */
	function verifyMessage($message, $eml) {
		$userCert = '';
		$tmpUserCert = tempnam(sys_get_temp_dir(), true);
		$importMessageCert = false;

		// TODO: worth to split fetching public certificate in a seperate function?

		// Public certificate from GAB in combination with LDAP saved in PR_EMS_AB_TAGGED_X509_CERT
		// If GAB's PR_ENTRYID matches the PR_SENT_REPRESENTING_ENTRYID of a message, the users exists in GAB
		$ab = $GLOBALS['mapisession']->getAddressbook();
		$userEntryID = mapi_getprops($message, array(PR_SENT_REPRESENTING_ENTRYID));

		// When downloading an email as eml, $GLOBALS['operations'] isn't set, so add a check so that downloading works
		if(isset($GLOBALS['operations'])) {
			$senderAddressArray = $GLOBALS["operations"]->getSenderAddress($message);
			$senderAddressArray = $senderAddressArray['props'];
			if($senderAddressArray['address_type'] === 'SMTP') {
				$emailAddr = $senderAddressArray['email_address'];
			} else {
				$emailAddr = $senderAddressArray['smtp_address'];
			}

			if($emailAddr) {
				$userCert = base64_decode($this->getPublicKey($emailAddr));
				if(!empty($userCert)) { // Check MAPI UserStore
					file_put_contents($tmpUserCert, $userCert);
				}
			}
		}

		// If user entry exists in GAB, try to retrieve public cert from the MAPI property (LDAP)
		if (isset($userEntryID[PR_SENT_REPRESENTING_ENTRYID])) {
			$user = mapi_ab_openentry($ab, $userEntryID[PR_SENT_REPRESENTING_ENTRYID]);
			$userCertArray = mapi_getprops($user, array(PR_EMAIL_ADDRESS, PR_EMS_AB_TAGGED_X509_CERT));
			if(isset($userCertArray[PR_EMS_AB_TAGGED_X509_CERT])) {
				$userCert = $userCertArray[PR_EMS_AB_TAGGED_X509_CERT][0];
				$userCert = der2pem($userCert);
				file_put_contents($tmpUserCert, $userCert);
			}
		} 

		// Save signed message in a random file
		$tmpfname = tempnam(sys_get_temp_dir(), true);	
		file_put_contents($tmpfname, $eml);

		// Create random file for saving the signed message
		$outcert = tempnam(sys_get_temp_dir(), true);	

		// Verify signed message
		// Returns True if verified, False if tampered or signing certificate invalid OR -1 on error
		if(!empty($userCert)) {
			$signed_ok = openssl_pkcs7_verify($tmpfname, PKCS7_NOINTERN, $outcert, explode(';', PLUGIN_SMIME_CACERTS), $tmpUserCert);
			$openssl_error_code = $this->extract_openssl_error();
			$this->validateSignedMessage($signed_ok, $openssl_error_code);
			if($signed_ok && $openssl_error_code !== OPENSSL_CA_VERIFY_FAIL) { // CA Checks out
				// Check if we need to import a newer certificate
				$importCert = file_get_contents($outcert);
				$parsedImportCert = openssl_x509_parse($importCert);
				$parsedUserCert = openssl_x509_parse($userCert);

				// If validTo and validFrom are more in the future, emailAddress matches and OCSP check is valid, import newer certificate
				if($parsedImportCert['validTo'] > $parsedUserCert['validTo'] && $parsedImportCert['validFrom'] > $parsedUserCert['validFrom'] 
					&& getCertEmail($parsedImportCert) === getCertEmail($parsedUserCert) && $this->verifyOCSP($importCert)) {
					$importMessageCert = true;
				} else {
					$this->verifyOCSP($userCert);
				}
			}
		} else {
			$signed_ok = openssl_pkcs7_verify($tmpfname, PKCS7_NOSIGS, $outcert, explode(';', PLUGIN_SMIME_CACERTS));
			$openssl_error_code = $this->extract_openssl_error();
			$this->validateSignedMessage($signed_ok, $openssl_error_code);

			// OCSP check
			if($signed_ok && $openssl_error_code !== OPENSSL_CA_VERIFY_FAIL) { // CA Checks out
				$userCert = file_get_contents($outcert);
				$parsedImportCert = openssl_x509_parse($userCert);

				if(is_array($parsedImportCert) && $this->verifyOCSP($userCert)) {
					$importMessageCert = true;
				}
				// We don't have a certificate from the MAPI UserStore or LDAP, so we will set $userCert to $importCert
				// so that we can verify the message according to the be imported certificate.
			} else { // No pubkey
				$this->message['success'] = SMIME_STATUS_FAIL;
				$this->message['info'] = SMIME_CA;
			}
		}

		// Certificate is newer or not yet imported to the user store and not revoked
		if($importMessageCert) {
			// FIXME: doing this in importPublicKey too...
			$certEmail = getCertEmail($parsedImportCert);
			if(!empty($certEmail)) {
				$this->importCertificate($userCert, $parsedImportCert, 'public', True);
			}
		}

		// remove the temporary file
		unlink($tmpfname);

		// Clean up temp cert
		unlink($tmpUserCert);
	}

	/**
	 * Function which decrypts an encrypted message.
	 * The key should be unlocked and stored in the $_SESSION['smime'] for a successfull decrypt
	 * If the key isn't in the session, we give the user a message to unlock his certificate.
	 *
	 * @param {mixed} $data array of data from hook
	 */
	function onEncrypted($data) {
		// Cert unlocked, decode message
		$this->message['success'] = SMIME_STATUS_FAIL;
		$this->message['info'] = SMIME_DECRYPT_FAILURE;

		$this->message['type'] = 'encrypted';
		if(isset($_SESSION['smime']) && !empty($_SESSION['smime'])) {
			$certs = readPrivateCert($this->store, $_SESSION['smime']);

			// create random file for saving the encrypted and body message
			$tmpFile = tempnam(sys_get_temp_dir(), true);
			$tmpDecrypted = tempnam(sys_get_temp_dir(), true);

			// Write mime header. Because it's not provided in the attachment, otherwise openssl won't parse it
			$fp = fopen($tmpFile,'w');
			fwrite($fp, "Content-Type: application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data\n");
			fwrite($fp, "Content-Transfer-Encoding: base64\nContent-Disposition: attachment; filename=\"smime.p7m\"\n");
			fwrite($fp, "Content-Description: S/MIME Encrypted Message\n\n");
			fwrite($fp,chunk_split(base64_encode($data['data']), 72) . "\n");
			fclose($fp);

			// TODO: handle decryption failure
			openssl_pkcs7_decrypt($tmpFile, $tmpDecrypted, $certs['cert'], array($certs['pkey'], ''));

			$content = file_get_contents($tmpDecrypted);

			$receivedTime = mapi_getprops($data['message'], Array(PR_MESSAGE_DELIVERY_TIME));
			mapi_inetmapi_imtomapi($GLOBALS['mapisession']->getSession(), $this->store, $GLOBALS['mapisession']->getAddressbook(), $data['message'], $content, Array('parse_smime_signed' => True));
			// Manually set time back to the received time, since mapi_inetmapi_imtomapi overwrites this
			mapi_setprops($data['message'], $receivedTime);

			// remove temporary files
			unlink($tmpFile);
			unlink($tmpDecrypted);

			// mapi_inetmapi_imtomapi removes the PR_MESSAGE_CLASS = 'IPM.Note.SMIME.MultipartSigned'
			// So we need to check if the message was also signed by looking at the MIME_TAG in the eml
			if(strpos($content, 'multipart/signed') !== false) {
				$this->message['type'] = 'encryptsigned';
				$this->verifyMessage($data['message'], $content);
			} else {
				$this->message['info'] = SMIME_DECRYPT_SUCCESS;
				$this->message['success'] = SMIME_STATUS_SUCCESS;
			}

		} else {
			$this->message['info'] = SMIME_UNLOCK_CERT;
		}
		unset($_SESSION['smime']);
	}

	/**
	 * Function which calls verifyMessage to verify if the message isn't malformed during transport.
	 * 
	 * @param {mixed} $data array of data from hook
	 */
	function onSignedMessage($data) {
		$this->message['type'] = 'signed';
		$this->verifyMessage($data['message'], $data['data']);
	}

	/**
	 * General function which parses the openssl_pkcs7_verify return value and the errors generated by
	 * openssl_error_string()
	 */
	function validateSignedMessage($openssl_return, $openssl_errors) {
		if ($openssl_return === -1) {
			$this->message['info'] = SMIME_ERROR;
			$this->message['success'] = SMIME_STATUS_FAIL;
		// Verification was successful
		} else if ($openssl_return) {
			$this->message['info'] = SMIME_SUCCESS;
			$this->message['success'] = SMIME_STATUS_SUCCESS;
		// Verification was not successful, display extra information.
		} else {
			$this->message['success'] = SMIME_STATUS_FAIL;
			if ($openssl_errors === OPENSSL_CA_VERIFY_FAIL) {
				$this->message['info'] = SMIME_CA;
			} else { // Catch general errors
				$this->message['info'] = SMIME_ERROR;
			}
		}
	}

	/**
	 * Set smime key in $data array, which is send back to client
	 * Since we can't create this array key in the in the hooks:
	 * 'server.util.parse_smime.signed'
	 * 'server.util.parse_smime.encrypted'
	 *
	 * TODO: investigate if we can move away from this hook
	 * @param {mixed} $data
	 */
	function onAfterOpen($data) {
		if(isset($this->message) && !empty($this->message)) {
			$data['data']['item']['props']['smime'] = $this->message;
		}
	}

	/**
	 * Handles the uploaded certificate in the settingsmenu in the WebApp
	 * - Opens the certificate with provided passphrase
	 * - Checks if it can be used for signing/decrypting
	 * - Verifies that the email address is equal to the 
	 * - Verifies that the certificate isn't expired and inform user
	 *
	 * @param {mixed} $data
	 */
	function onUploadCertificate($data) {
		if($data['sourcetype'] === 'certificate') {
			$passphrase = $_POST['passphrase'];
			$saveCert = false;
			$tmpname = $data['tmpname'];
			$message = '';

			$certificate = file_get_contents($tmpname);
			if(openssl_pkcs12_read($certificate, $certs, $passphrase)) {
				$privatekey = $certs['pkey'];
				$publickey = $certs['cert'];

				$publickeyData = openssl_x509_parse($publickey);

				if($publickeyData) {
					$certEmailAddress = getCertEmail($publickeyData);
					$validFrom = $publickeyData['validFrom_time_t'];
					$validTo = $publickeyData['validTo_time_t'];
					$emailAddress = $GLOBALS['mapisession']->getSMTPAddress();

					// Check priv key for signing capabilities
					if(!openssl_x509_checkpurpose($privatekey, X509_PURPOSE_SMIME_SIGN)) {
						$message = _('Private key can\'t be used to sign email', 'plugin_smime');
					}
					// Check if the certificate owner matches the WebApp users email address
					else if($certEmailAddress !== $emailAddress) {
						$message = _('Certificate email address doesn\'t match WebApp account ', 'plugin_smime') . $certEmailAddress;
					}
					// Check if certificate is not expired, still import the certificate since a user wants to decrypt his old email
					else if($validTo < time()) {
						$message = _('Certificate was expired on ') . date('Y-m-d', $validTo) .  '. ' . _('Certificate has not been imported', 'plugin_smime');
					}
					// Check if the certificate is validFrom date is not in the future
					else if($validFrom > time()) {
						$message = _('Certificate is not yet valid ') . date('Y-m-d', $validFrom) . '. ' . _('Certificate has not been imported', 'plugin_smime');
					}
					// We allow users to import private certificate which have no OCSP support
					else if(!$this->verifyOCSP($certs['cert']) && $this->message['info'] !== SMIME_OCSP_NOSUPPORT) {
						$message = _('Certificate is revoked', 'plugin_smime');
					}
				} else { // Can't parse public certificate pkcs#12 file might be corrupt
					$message = _('Unable to read public certificate', 'plugin_smime');
				}
			} else { // Not able to decrypt email
				$message = _('Unable to decrypt certificate', 'plugin_smime');
			}

			// All checks completed succesfull
			// Store private cert in users associated store (check for duplicates)
			if(empty($message)) {
				$certMessage = getMAPICert($this->store);
				// TODO: update to serialNumber check
				if($certMessage && $certMessage[PR_MESSAGE_DELIVERY_TIME] == $validTo) {
					$message = _('Certificate is already stored on the server', 'plugin_smime');
				} else {
					$saveCert = true;
					$root = mapi_msgstore_openentry($this->store, null);
					// Remove old certificate
					if($certMessage) {
						// Delete private key
						mapi_folder_deletemessages($root, array($certMessage[PR_ENTRYID]));

						// Delete public key
						$pubCert = getMAPICert($this->store, 'WebApp.Security.Public', getCertEmail($certMessage));
						if($pubCert) {
							mapi_folder_deletemessages($root, array($pubCert[PR_ENTRYID]));
						}
						$message = _('New certificate uploaded', 'plugin_smime');
					} else {
						$message = _('Certificate uploaded', 'plugin_smime');
					}

					$this->importCertificate($certificate, $publickeyData, 'private');
					$this->importCertificate($publickey, $publickeyData);
				}
			}

			$returnfiles = array();
			$returnfiles[] = Array(
				'props' => Array(
					'attach_num' => -1,
					'size' => $data['size'],
					'name' => $data['name'],
					'cert' => $saveCert, 
					'cert_warning' => $message,
				)
			);
			$data['returnfiles'] = $returnfiles;
		}
	}

	/**
	 * This function handles the 'beforesend' hook which is triggered before sending the email.
	 * If the PR_MESSAGE_CLASS is set to a signed email (IPM.Note.SMIME.Multipartsigned), this function
	 * will convert the mapi message to RFC822, sign the eml and attach the signed email to the mapi message.
	 *
	 * @param {mixed} $data from php hook
	 */
	function onBeforeSend(&$data) 
	{
		$store = $data['store'];
		$message = $data['message'];

		// Retrieve message class
		$props = mapi_getprops($message, array(PR_MESSAGE_CLASS, PR_EC_IMAP_EMAIL));
		$messageClass = $props[PR_MESSAGE_CLASS];

		if(isset($messageClass) && (stripos($messageClass, 'IPM.Note.SMIME') !== false)) {
			// FIXME: for now return when we are going to sign but we don't have the passphrase set
			// This should never happen sign 
			if(($messageClass === 'IPM.Note.SMIME.SignedEncrypt' || $messageClass === 'IPM.Note.SMIME.MultipartSigned') && 
				!isset($_SESSION['smime'])) {
				return;
			}
			// NOTE: setting message class to IPM.Note, so that mapi_inetmapi_imtoinet converts the message to plain email
			// and doesn't fail when handling the attachments.
			mapi_setprops($message, array(PR_MESSAGE_CLASS => 'IPM.Note'));

			// If RFC822-formatted stream is already available in PR_EC_IMAP_EMAIL property
			// than directly use it, generate otherwise.
			if(isset($props[PR_EC_IMAP_EMAIL]) || propIsError(PR_EC_IMAP_EMAIL, $props) == MAPI_E_NOT_ENOUGH_MEMORY) {
				// Stream the message to properly get the PR_EC_IMAP_EMAIL property
				$emlMessageStream = mapi_openproperty($message, PR_EC_IMAP_EMAIL, IID_IStream, 0, 0);
			} else {
				// Read the message as RFC822-formatted e-mail stream.
				$emlMessageStream = mapi_inetmapi_imtoinet($GLOBALS['mapisession']->getSession(), $GLOBALS['mapisession']->getAddressbook(), $message, array());
			}

			// Remove all attachments, since they are stored in the attached signed message
			$atable = mapi_message_getattachmenttable($message);
			$rows = mapi_table_queryallrows($atable, Array(PR_ATTACH_MIME_TAG, PR_ATTACH_NUM));
			foreach($rows as $row) {
				$attnum = $row[PR_ATTACH_NUM];
				mapi_message_deleteattach($message, $attnum);
			}

			// create temporary files
			$tmpSendEmail = tempnam(sys_get_temp_dir(),true);
			$tmpSendSmimeEmail = tempnam(sys_get_temp_dir(),true);

			// Save message stream to a file
			$stat = mapi_stream_stat($emlMessageStream);
			
			$fhandle = fopen($tmpSendEmail,'w');
			$buffer = null;
			for($i = 0; $i < $stat["cb"]; $i += BLOCK_SIZE) {
				// Write stream
				$buffer = mapi_stream_read($emlMessageStream, BLOCK_SIZE);
				fwrite($fhandle,$buffer,strlen($buffer));
			}
			fclose($fhandle);
			
			// Create attachment for S/MIME message
			$signedAttach = mapi_message_createattach($message);
			$smimeProps = Array(
				PR_ATTACH_LONG_FILENAME => 'smime.p7m',
				PR_DISPLAY_NAME => 'smime.p7m',
				PR_ATTACH_METHOD => ATTACH_BY_VALUE,
				PR_ATTACH_MIME_TAG => 'multipart/signed',
				PR_ATTACHMENT_HIDDEN => true
			);

			// Sign then Encrypt email
			switch($messageClass) {
				case 'IPM.Note.SMIME.SignedEncrypt':
					$tmpFile = tempnam(sys_get_temp_dir(), true);
					$this->sign($tmpSendEmail, $tmpFile, $message, $signedAttach, $smimeProps);
					$this->encrypt($tmpFile, $tmpSendSmimeEmail, $message, $signedAttach, $smimeProps);
					unlink($tmpFile);
					break;
				case 'IPM.Note.SMIME.MultipartSigned':
					$this->sign($tmpSendEmail, $tmpSendSmimeEmail, $message, $signedAttach, $smimeProps);
					break;
				case 'IPM.Note.SMIME':
					$this->encrypt($tmpSendEmail, $tmpSendSmimeEmail, $message, $signedAttach, $smimeProps);
					break;
			}

			// Save the signed message as attachment of the send email
			$stream = mapi_openproperty($signedAttach, PR_ATTACH_DATA_BIN, IID_IStream, 0, MAPI_CREATE | MAPI_MODIFY);
			$handle = fopen($tmpSendSmimeEmail, 'r');
			while (!feof($handle)) {
				$contents = fread($handle, BLOCK_SIZE);
				mapi_stream_write($stream, $contents);
			}
			fclose($handle);

			mapi_stream_commit($stream);

			// remove tmp files
			unlink($tmpSendSmimeEmail);
			unlink($tmpSendEmail);

			mapi_savechanges($signedAttach);
			mapi_savechanges($message);
		}
	}

	/**
	 * Function to sign an email.
	 *
	 * @param object $infile File eml to be encrypted
	 * @param object $outfile File 
	 * @param object $message Mapi Message Object
	 * @param object $signedAttach
	 * @param array  $smimeProps 
	 */
	function sign(&$infile, &$outfile, &$message, &$signedAttach, $smimeProps)
	{
		// Set mesageclass back to IPM.Note.SMIME.MultipartSigned
		mapi_setprops($message, array(PR_MESSAGE_CLASS => 'IPM.Note.SMIME.MultipartSigned'));
		mapi_setprops($signedAttach, $smimeProps);

		// Obtain private certificate
		$certs = readPrivateCert($this->store, $_SESSION['smime']);

		openssl_pkcs7_sign($infile, $outfile, $certs['cert'], array($certs['pkey'], ''), array());
	}

	/**
	 * Function to encrypt an email.
	 *
	 * @param object $infile File eml to be encrypted
	 * @param object $outfile File 
	 * @param object $message Mapi Message Object
	 * @param object $signedAttach
	 * @param array  $smimeProps 
	 */
	function encrypt(&$infile, &$outfile, &$message, &$signedAttach, $smimeProps)
	{
		mapi_setprops($message, array(PR_MESSAGE_CLASS => 'IPM.Note.SMIME'));
		$smimeProps[PR_ATTACH_MIME_TAG] = "application/pkcs7-mime";
		mapi_setprops($signedAttach, $smimeProps);

		$publicCerts = $this->getPublicKeyForMessage($message);

		openssl_pkcs7_encrypt($infile, $outfile, $publicCerts, array(), 0, $this->cipher);
		$tmpEml = file_get_contents($outfile);

		// Grab the base64 data, since MAPI requires it saved as decoded base64 string.
		// FIXME: we can do better here
		$matches = explode("\n\n", $tmpEml);
		$base64 = str_replace("\n", "", $matches[1]);
		file_put_contents($outfile, base64_decode($base64));

		// Empty the body
		mapi_setprops($message, array(PR_BODY => ""));
	}
	
	/**
	 * Function which fetches the public certificates for all recipients (TO/CC/BCC) of a message
	 *
	 * @param object $message Mapi Message Object
	 * @return array of public certificates 
	 */
	function getPublicKeyForMessage($message) {
		$recipientTable = mapi_message_getrecipienttable($message);
		$recips = mapi_table_queryallrows($recipientTable, Array(PR_SMTP_ADDRESS, PR_RECIPIENT_TYPE), Array(RES_OR, Array(
			Array(RES_PROPERTY, 
				Array(
					RELOP => RELOP_EQ,
					ULPROPTAG => PR_RECIPIENT_TYPE,
					VALUE => MAPI_BCC
				),
			),
			Array(RES_PROPERTY,
				Array(
					RELOP => RELOP_EQ,
					ULPROPTAG => PR_RECIPIENT_TYPE,
					VALUE => MAPI_CC
				),
			),
			Array(RES_PROPERTY,
				Array(
					RELOP => RELOP_EQ,
					ULPROPTAG => PR_RECIPIENT_TYPE,
					VALUE => MAPI_TO
				),
			),
		)));

		$publicCerts = Array();
		foreach($recips as $recip) {
			// TOOD: error handling?
			$emailAddr = $recip[PR_SMTP_ADDRESS];
			array_push($publicCerts, base64_decode($this->getPublicKey($emailAddr)));
		}

		return $publicCerts;
	}

	/**
	 * Retrieves the public certificate stored in the MAPI UserStore and belonging to the
	 * emailAdddress, returns "" if there is no certificate for that user.
	 *
	 * @param {String} emailAddress
	 * @return {String} $certificate 
	 *
	 */
	function getPublicKey($emailAddress)
	{
		$certificate = "";

		$cert = getMAPICert($this->store, 'WebApp.Security.Public', $emailAddress);

		if($cert) {
			$pubkey = mapi_msgstore_openentry($this->store, $cert[PR_ENTRYID]);

			if($pubkey != false) {
				// retreive pkcs#11 certificate from body
				$stream = mapi_openproperty($pubkey, PR_BODY, IID_IStream, 0, 0);
				$stat = mapi_stream_stat($stream);
				mapi_stream_seek($stream, 0, STREAM_SEEK_SET);
				for ($i = 0; $i < $stat['cb']; $i += 1024) {
					$certificate .= mapi_stream_read($stream,1024);
				}
			}
		}
		return $certificate;
	}

	/**
	 * Function which is used to check if there is a public certificate for the provided emailAddress
	 * 
	 * @param {String} emailAddress emailAddres of recipient
	 * @return {Boolean} true if public certificate exists
	 */
	function pubcertExists($emailAddress) 
	{
		$root = mapi_msgstore_openentry($this->store, null);
		$table = mapi_folder_getcontentstable($root, MAPI_ASSOCIATED);

		// Restriction for public certificates which are from the sender of the email, are active and have the correct message_class
		$restrict = array(RES_AND, array(
			array(RES_PROPERTY,
				array(
					RELOP => RELOP_EQ, 
					ULPROPTAG => PR_MESSAGE_CLASS,
					VALUE => array(PR_MESSAGE_CLASS => "Webapp.Security.Public")
				),
			),
			array(RES_PROPERTY,
				array(
					RELOP => RELOP_EQ,
					ULPROPTAG => PR_SUBJECT,
					VALUE => array(PR_SUBJECT => $emailAddress)
				),
			)
		));
		mapi_table_restrict($table, $restrict, TBL_BATCH);
		mapi_table_sort($table, array(PR_MESSAGE_DELIVERY_TIME => TABLE_SORT_DESCEND), TBL_BATCH);

		$rows = mapi_table_queryallrows($table, array(PR_SUBJECT, PR_ENTRYID, PR_MESSAGE_DELIVERY_TIME, PR_CLIENT_SUBMIT_TIME), $restrict);
		return !empty($rows);
	}

	/**
	 * Helper functions which extracts the errors from openssl_error_string()
	 * Example error from openssl_error_string(): error:21075075:PKCS7 routines:PKCS7_verify:certificate verify error
	 * Note that openssl_error_string() returns an error when verifying is successful, this is a bug in PHP https://bugs.php.net/bug.php?id=50713
	 * @return {String} 
	 */
	function extract_openssl_error() {
		// TODO: should catch more erros by using while($error = @openssl_error_string())
		$openssl_error = @openssl_error_string();
		$openssl_error_code = 0;
		if($openssl_error) {
			$openssl_error_list = explode(":", $openssl_error);
			$openssl_error_code = $openssl_error_list[1];
		}
		return $openssl_error_code;
	}

	/**
	 * Function which does an OCSP/CRL check on the certificate to find out if it has been
	 * revoked.
	 * 
	 * For an OCSP request we need the following items:
	 * - Client certificate which we need to verify
	 * - Issuer certificate (Authority Information Access: Ca Issuers) openssl x509 -in certificate.crt -text
	 * - OCSP URL (Authority Information Access: OCSP Url)
	 *
	 * The issuer certificate is fetched once and stored in /var/lib/kopano-webapp/tmp/smime
	 * We create the directory if it does not exists, check if the certificate is already stored. If it is already
	 * stored we, use stat() to determine if it is not very old (> 1 Month) and otherwise fetch the certificate and store it.
	 *
	 * @param {String} $certificate
	 * @return {Boolean} true is OCSP verification has succeeded or when there is no OCSP support, false if it hasn't
	 */
	function verifyOCSP($certificate) {
		if(!PLUGIN_SMIME_ENABLE_OCSP) {
			$this->message['success'] = SMIME_STATUS_SUCCESS;
			$this->message['info'] = SMIME_OCSP_DISABLED;
			return true;
		}

		$issuerStore = '/var/lib/kopano-webapp/tmp/smime';
		$this->message['success'] = SMIME_STATUS_FAIL;
		if (!file_exists($issuerStore)) {
			mkdir($issuerStore, 0755);
		}

		$certProps = openssl_x509_parse($certificate);
		// Check if extensions key exists
		if(isset($certProps['extensions']) && !empty($certProps['extensions']) && !empty($certProps['extensions']['authorityInfoAccess'])) {
			if(preg_match("/CA Issuers - URI:(.*)/", $certProps['extensions']['authorityInfoAccess'], $matches)) {
				$caUrl = array_pop($matches);
			}
			if(preg_match("/OCSP - URI:(.*)/", $certProps['extensions']['authorityInfoAccess'], $matches)) {
				$ocspUrl = array_pop($matches);
			}
			if(!empty($ocspUrl)) {
				$issuerFile = $issuerStore . '/' . end((explode('/', $caUrl)));

				// If file exists and the file is modified 1 week ago, fetch a new certificate
				if(!file_exists($issuerFile) || (file_exists($issuerFile) && filemtime($issuerFile) < (time() - 604800))) {
					// FIXME: Handle 404? 
					$ch = curl_init(); 
					curl_setopt($ch, CURLOPT_URL, $caUrl); 
					curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); 
					$output = curl_exec($ch); 
					curl_close($ch);      
					// Note certificate is saved in DER format
					file_put_contents($issuerFile, $output);
				}

				// Set custom error handler since the nemid ocsp library uses trigger_error() to throw errors when it 
				// can parse certain x509 fields which aare not required for the OCSP Reuqest.
				// Also when receiving the OCSP request, the OCSP library triggers errors when the request does not adhere
				// the standard.
				function tempErrorHandler($errno, $errstr, $errfile, $errline){
					return true;
				}
				set_error_handler("tempErrorHandler");

				// Load certificates
				$x509 = new \WAYF\X509();
				$issuer = $x509->certificate(file_get_contents($issuerFile));
				$certificate = $x509->certificate(pem2der($certificate));

				$ocspclient = new \WAYF\OCSP();

				$certID = $ocspclient->certOcspID(array(
					    'issuerName' => $issuer['tbsCertificate']['subject_der'],
					    // remember to skip the first byte it is the number of unused bits and it is alwayf 0 for keys and certificates
					    'issuerKey' => substr($issuer['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'], 1),
					    'serialNumber_der' => $certificate['tbsCertificate']['serialNumber_der']),
					    'sha1'
				);
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
				$derresponse = file_get_contents($ocspUrl, null, $context);
				// OCSP service not avaliable, import certificate, but show a warning.
				if($derresponse === false) {
					$this->message['info'] = SMIME_OCSP_FAILED;
					$this->message['success'] = SMIME_STATUS_PARTIAL;
					return true;
				}
				$ocspresponse = $ocspclient->response($derresponse);

				// Restore the previous error handler
				restore_error_handler();

				if(isset($ocspresponse['responseStatus']) && 
					$ocspresponse['responseStatus'] !== 'successful') {
					// Certificate status is not good, revoked or unknown
					$this->message['info'] = SMIME_REVOKED;
					return false;
				}

				$resp = $ocspresponse['responseBytes']['BasicOCSPResponse']['tbsResponseData']['responses'][0];

				/* OCSP response status, possible values are: good, revoked, unknown according
				 * to the RFC https://www.ietf.org/rfc/rfc2560.txt
				 */
				if($resp['certStatus'] !== 'good') {
					// Certificate status is not good, revoked or unknown
					$this->message['info'] = SMIME_REVOKED;
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
					$this->message['info'] = SMIME_REVOKED;
					return false;
				}

				// check if OCSP revocation update is recent
				$now = gmdate('YmdHis\Z');
				if($resp['thisUpdate'] >= $now && $now >= $resp['nextupdate']) {
					// OCSP Revocation status not current
					$this->message['info'] = SMIME_REVOKED;
					return false;
				}

				$this->message['success'] = SMIME_STATUS_SUCCESS;
				return true;
			}
		}
		// Certificate does not support OCSP
		$this->message['info'] = SMIME_SUCCESS;
		$this->message['success'] = SMIME_STATUS_SUCCESS;
		return true;
	}

	/**
	 * Imports certificate in the MAPI Root Associated Folder
	 *
	 * Private key, always insert certificate
	 * Public key, check if we already have one stored
	 *
	 * @param string $cert certificate body as a string
	 * @param mixed  $certData an array with the parsed certificate data
	 * @param string $type certificate type, default 'public'
	 * @param bool   $force force import the certificate even though we have one already stored in the MAPI Store. 
	 * FIXME: remove $force in the future and move the check for newer certificate in this function.
	 */
	function importCertificate($cert, $certData, $type = 'public', $force = False)
	{
		$certEmail = getCertEmail($certData);
		if(!$this->pubCertExists($certEmail) || $force || $type === 'private'){

			$issued_by = "";
			foreach(array_keys($certData['issuer']) as $key) {
				$issued_by .= $key . '=' . $certData['issuer'][$key] . "\n";
			}

			$issued_to = "";
			foreach(array_keys($certData['subject']) as $key) {
				if($key !== 'emailAddress') {
					$issued_to .= $key . '=' . $certData['subject'][$key] . "\n";
				}
			}

			$root = mapi_msgstore_openentry($this->store, null);
			$assocMessage = mapi_folder_createmessage($root, MAPI_ASSOCIATED);
			// TODO: write these properties down.
			mapi_setprops($assocMessage, array(
				PR_SUBJECT => getCertEmail($certData),
				PR_MESSAGE_CLASS => $type == 'public' ? 'Webapp.Security.Public' : 'WebApp.Security.Private',
				PR_MESSAGE_DELIVERY_TIME => $certData['validTo_time_t'],
				PR_CLIENT_SUBMIT_TIME => $certData['validFrom_time_t'],
				PR_SENDER_NAME => $certData['serialNumber'], // serial
				PR_SENDER_EMAIL_ADDRESS => $issued_by, // Issuer To
				PR_SUBJECT_PREFIX => $issued_to,
				PR_RECEIVED_BY_NAME => $this->fingerprint_cert($cert, 'sha1'), // SHA1 Fingerprint
				PR_INTERNET_MESSAGE_ID => $this->fingerprint_cert($cert) // MD5 FingerPrint
			));
			// Save attachment
			$msgBody = base64_encode($cert);
			$stream = mapi_openpropertytostream($assocMessage, PR_BODY, MAPI_CREATE | MAPI_MODIFY);
			mapi_stream_setsize($stream, strlen($msgBody));
			mapi_stream_write($stream, $msgBody);
			mapi_stream_commit($stream);
			mapi_message_savechanges($assocMessage);
		}
	}

	/**
	 * Function which returns the fingerprint (hash) of the certificate
	 *
	 * @param {string} $cert certificate body as a string
	 * @param {string} $hash optional hash algorithm
	 */
	function fingerprint_cert($body, $hash = 'md5')
	{
		// TODO: Note for PHP > 5.6 we can use openssl_x509_fingerprint
		$body = str_replace('-----BEGIN CERTIFICATE-----', '', $body);
		$body = str_replace('-----END CERTIFICATE-----', '', $body);
		$body = base64_decode($body);

		if($hash === 'sha1') {
			$fingerprint = sha1($body);
		} else {
			$fingerprint = md5($body);
		}

		// Format 1000AB as 10:00:AB
		return strtoupper(implode(':', str_split($fingerprint, 2)));
	}

	/**
	 * Called when the core Settings class is initialized and ready to accept sysadmin default 
	 * settings. Registers the sysadmin defaults for the example plugin.
	 *
	 * @param {mixed} $data Reference to the data of the triggered hook
	 */
	function onBeforeSettingsInit(&$data){
		$data['settingsObj']->addSysAdminDefaults(Array(
			'zarafa' => Array(
				'v1' => Array(
					'plugins' => Array(
						'smime' => Array(
							'enable' => PLUGIN_SMIME_USER_DEFAULT_ENABLE_SMIME,
						)
					)
				)
			)
		));
	}
}
?>
