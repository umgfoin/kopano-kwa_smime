<?php
include_once('util.php');
require_once('class.certificate.php');

// Green, everything was good
define('SMIME_STATUS_SUCCESS', 0);
// Orange, CA is missing or OCSP is not avaliable
define('SMIME_STATUS_PARTIAL', 1);
// Red, something really went wrong
define('SMIME_STATUS_FAIL', 2);
// Blue, info message
define('SMIME_STATUS_INFO', 3);

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
define('SMIME_DECRYPT_CERT_MISMATCH', 12);

// OpenSSL Error Constants
// openssl_error_string() returns error codes when an operation fails, since we return custom error strings
// in our plugin we keep a list of openssl error codes in these defines
define('OPENSSL_CA_VERIFY_FAIL', '21075075');
define('OPENSSL_RECIPIENT_CERTIFICATE_MISMATCH', '21070073');

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
		$this->registerHook('server.index.load.custom');

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
			case 'server.index.load.custom':
				if ( $data['name'] === 'smime_passphrase' ){
					include('templates/passphrase.tpl.php');
					die();
				}
				if ( $data['name'] === 'smime_passphrasecheck' ){
					// No need to do anything, this is just used to trigger
					// the browser's autofill save password dialog.
					die();
				}
				break;
		}
	}

	/**
	 * Function checks if public certificate exists for all recipients and creates an error
	 * message for the frontend which includes the email address of the missing public
	 * certificates.
	 *
	 * If my own certificate is missing, a different error message is shown which informs the
	 * user that his own public certificate is missing and required for reading encrypted emails
	 * in the 'Sent items' folder.
	 *
	 * @param Array $data Reference to the data of the triggered hook
	 */
	function onCertificateCheck($data) {
		$entryid = $data['entryid'];
		// FIXME: unittests, save trigger will pass $entryid is 0 (which will open the root folder and not the message we want)
		if ($entryid === false) {
			return;
		}

		$message = mapi_msgstore_openentry($this->store, $entryid);
		$module = $data['moduleObject'];
		$data['success'] = true;

		$messageClass = mapi_getprops($message, array(PR_MESSAGE_CLASS));
		$messageClass = $messageClass[PR_MESSAGE_CLASS];
		if ($messageClass !== 'IPM.Note.SMIME' && $messageClass !== 'IPM.Note.SMIME.SignedEncrypt') {
			return;
		}

		$recipients = $data['action']['props']['smime'];
		$missingCerts = [];

		foreach($recipients as $recipient) {
			$email = $recipient['email'];

			if (!$this->pubcertExists($email, $recipient['internal'])) {
				array_push($missingCerts, $email);
			}
		}

		if (empty($missingCerts)) {
			return;
		}

		function missingMyself($email) {
			return $GLOBALS['mapisession']->getSMTPAddress() === $email;
		}

		if (array_filter($missingCerts, "missingMyself") === []) {
			$errorMsg = dgettext('plugin_smime', 'Missing public certificates for the following recipients: ') . implode(', ', $missingCerts) . dgettext('plugin_smime', '. Please contact your system administrator for details');
		} else {
			$errorMsg = dgettext("plugin_smime", "Your public certificate is not installed. Without this certificate, you will not be able to read encrypted messages you have sent to others.");
		}
		
		$module->sendFeedback(false, array("type" => ERROR_GENERAL, "info" => array('display_message' => $errorMsg)));
		$data['success'] = false;
	}

	/**
	 * Function which verifies a message
	 *
	 */
	function verifyMessage($message, $eml) {
		$userCert = '';
		$tmpUserCert = tempnam(sys_get_temp_dir(), true);
		$importMessageCert = false;
		$fromGAB = false;

		// TODO: worth to split fetching public certificate in a seperate function?

		// If user entry exists in GAB, try to retrieve public cert
		// Public certificate from GAB in combination with LDAP saved in PR_EMS_AB_TAGGED_X509_CERT
		$userEntryID = mapi_getprops($message, array(PR_SENT_REPRESENTING_ENTRYID));

		if (isset($userEntryID[PR_SENT_REPRESENTING_ENTRYID])) {
			$user = mapi_ab_openentry($GLOBALS['mapisession']->getAddressbook(), $userEntryID[PR_SENT_REPRESENTING_ENTRYID]);

			$gabCert = $this->getGABCert($user);
			if (!empty($gabCert)) {
				$fromGAB = true;
				file_put_contents($tmpUserCert, $userCert);
			}
		}

		// When downloading an email as eml, $GLOBALS['operations'] isn't set, so add a check so that downloading works
		// If the certificate is already fetch from the GAB, skip checking the userStore.
		if (!$fromGAB && isset($GLOBALS['operations'])) {
			$senderAddressArray = $this->getSenderAddress($message);
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
		// If certificate is from the GAB, then don't import it.
		if ($importMessageCert && !$fromGAB) {
			// FIXME: doing this in importPublicKey too...
			$certEmail = getCertEmail($parsedImportCert);
			if(!empty($certEmail)) {
				$this->importCertificate($userCert, $parsedImportCert, 'public', True);
			}
		}

		// Remove extracted certificate from openssl_pkcs7_verify
		unlink($outcert);

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
		$this->message['success'] = SMIME_STATUS_INFO;
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

			$decryptStatus = openssl_pkcs7_decrypt($tmpFile, $tmpDecrypted, $certs['cert'], array($certs['pkey'], ''));

			$content = file_get_contents($tmpDecrypted);
			// Handle OL empty body Outlook Signed & Encrypted mails.
			// The S/MIME plugin has to extract the body from the signed message.
			if (strpos($content, 'signed-data') !== false) {
				$this->message['type'] = 'encryptsigned';
				$olcert = tempnam(sys_get_temp_dir(), true);
				$olmsg = tempnam(sys_get_temp_dir(), true);
				openssl_pkcs7_verify($tmpDecrypted, PKCS7_NOVERIFY, $olcert);
				openssl_pkcs7_verify($tmpDecrypted, PKCS7_NOVERIFY, $olcert, array(), $olcert, $olmsg);
				$content = file_get_contents($olmsg);
				unlink($olmsg);
				unlink($olcert);
			}

			$receivedTime = mapi_getprops($data['message'], Array(PR_MESSAGE_DELIVERY_TIME));
			mapi_inetmapi_imtomapi($GLOBALS['mapisession']->getSession(), $this->store, $GLOBALS['mapisession']->getAddressbook(), $data['message'], $content, Array('parse_smime_signed' => True));
			// Manually set time back to the received time, since mapi_inetmapi_imtomapi overwrites this
			mapi_setprops($data['message'], $receivedTime);

			// remove duplicate recipients
			$this->removeDuplicateRecipients($data['message']);

			// remove temporary files
			unlink($tmpFile);
			unlink($tmpDecrypted);

			// mapi_inetmapi_imtomapi removes the PR_MESSAGE_CLASS = 'IPM.Note.SMIME.MultipartSigned'
			// So we need to check if the message was also signed by looking at the MIME_TAG in the eml
			if(strpos($content, 'multipart/signed') !== false || strpos($content, 'signed-data') !== false) {
				$this->message['type'] = 'encryptsigned';
				$this->verifyMessage($data['message'], $content);
			} else if ($decryptStatus) {
				$this->message['info'] = SMIME_DECRYPT_SUCCESS;
				$this->message['success'] = SMIME_STATUS_SUCCESS;
			} else if ($this->extract_openssl_error() === OPENSSL_RECIPIENT_CERTIFICATE_MISMATCH) {
				$this->message['info'] = SMIME_DECRYPT_CERT_MISMATCH;
				$this->message['success'] = SMIME_STATUS_FAIL;
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
						$message = dgettext('plugin_smime', 'Private key can\'t be used to sign email');
					}
					// Check if the certificate owner matches the WebApp users email address
					else if (strcasecmp($certEmailAddress, $emailAddress) !== 0) {
						$message = dgettext('plugin_smime', 'Certificate email address doesn\'t match WebApp account ') . $certEmailAddress;
					}
					// Check if certificate is not expired, still import the certificate since a user wants to decrypt his old email
					else if($validTo < time()) {
						$message = dgettext('plugin_smime', 'Certificate was expired on ') . date('Y-m-d', $validTo) .  '. ' . dgettext('plugin_smime', 'Certificate has not been imported');
					}
					// Check if the certificate is validFrom date is not in the future
					else if($validFrom > time()) {
						$message = dgettext('plugin_smime', 'Certificate is not yet valid ') . date('Y-m-d', $validFrom) . '. ' . dgettext('plugin_smime', 'Certificate has not been imported');
					}
					// We allow users to import private certificate which have no OCSP support
					else if(!$this->verifyOCSP($certs['cert']) && $this->message['info'] !== SMIME_OCSP_NOSUPPORT) {
						$message = dgettext('plugin_smime', 'Certificate is revoked');
					}
				} else { // Can't parse public certificate pkcs#12 file might be corrupt
					$message = dgettext('plugin_smime', 'Unable to read public certificate');
				}
			} else { // Not able to decrypt email
				$message = dgettext('plugin_smime', 'Unable to decrypt certificate');
			}

			// All checks completed succesfull
			// Store private cert in users associated store (check for duplicates)
			if(empty($message)) {
				$certMessage = getMAPICert($this->store);
				// TODO: update to serialNumber check
				if($certMessage && $certMessage[PR_MESSAGE_DELIVERY_TIME] == $validTo) {
					$message = dgettext('plugin_smime', 'Certificate is already stored on the server');
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
						$message = dgettext('plugin_smime', 'New certificate uploaded');
					} else {
						$message = dgettext('plugin_smime', 'Certificate uploaded');
					}

					$this->importCertificate($certificate, $publickeyData, 'private');

					// Check if the user has an public key in the GAB.
					$store_props = mapi_getprops($this->store, array(PR_USER_ENTRYID));
					$user = mapi_ab_openentry($GLOBALS['mapisession']->getAddressbook(), $store_props[PR_USER_ENTRYID]);

					$gabCert = $this->getGABCert($user);
					if (empty($gabCert)) {
						$this->importCertificate($publickey, $publickeyData);
					}
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

		// Retrieve intermediate CA's for verification, if avaliable
		if (isset($certs['extracerts'])) {
			$tmpFile = tempnam(sys_get_temp_dir(), true);
			file_put_contents($tmpFile, implode('', $certs['extracerts']));
			$ok = openssl_pkcs7_sign($infile, $outfile, $certs['cert'], array($certs['pkey'], ''), array(), PKCS7_DETACHED, $tmpFile);
			unlink($tmpFile);
		} else {
			$ok = openssl_pkcs7_sign($infile, $outfile, $certs['cert'], array($certs['pkey'], ''), array(), PKCS7_DETACHED);
		}
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
		// Always append our own certificate, so that the mail can be decrypted in 'Sent items'
		array_push($publicCerts, base64_decode($this->getPublicKey($GLOBALS['mapisession']->getSMTPAddress())));

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
		$recips = mapi_table_queryallrows($recipientTable, Array(PR_SMTP_ADDRESS, PR_RECIPIENT_TYPE, PR_ADDRTYPE), Array(RES_OR, Array(
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
		$storeCert = '';
		$gabCert = '';

		foreach($recips as $recip) {
			$emailAddr = $recip[PR_SMTP_ADDRESS];

			if ($recip[PR_ADDRTYPE] === "ZARAFA") {
				$user = $this->getGABUser($emailAddr);
				$gabCert = $this->getGABCert($user);
			}

			$storeCert = $this->getPublicKey($emailAddr);

			if (!empty($gabCert)) {
				array_push($publicCerts, $gabCert);
			} else if (!empty($storeCert)) {
				array_push($publicCerts, base64_decode($storeCert));
			}

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
	 * @param {Boolean} gabUser is the user of PR_ADDRTYPE == ZARAFA.
	 * @return {Boolean} true if public certificate exists
	 */
	function pubcertExists($emailAddress, $gabUser = false)
	{
		if ($gabUser) {
			$user = $this->getGABUser($emailAddress);
			$gabCert = $this->getGABCert($user);
			if ($user && !empty($gabCert)) {
				return True;
			}
		}

		$root = mapi_msgstore_openentry($this->store, null);
		$table = mapi_folder_getcontentstable($root, MAPI_ASSOCIATED);

		// Restriction for public certificates which are from the sender of the email, are active and have the correct message_class
		$restrict = array(RES_AND, array(
			array(RES_PROPERTY,
				array(
					RELOP => RELOP_EQ,
					ULPROPTAG => PR_MESSAGE_CLASS,
					VALUE => array(PR_MESSAGE_CLASS => "WebApp.Security.Public")
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

		if (!PLUGIN_SMIME_ENABLE_OCSP) {
			$this->message['success'] = SMIME_STATUS_SUCCESS;
			$this->message['info'] = SMIME_OCSP_DISABLED;
			return true;
		}

		$cert = new Certificate($certificate);

		# FIXME: cache issue certificate.
		if (!$cert->verify() || !$cert->issuer()->verify()) {
			$this->message['info'] = SMIME_REVOKED;
			$this->message['success'] = SMIME_STATUS_PARTIAL;
			return false;
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
		if(!$this->pubcertExists($certEmail) || $force || $type === 'private'){

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
				PR_MESSAGE_CLASS => $type == 'public' ? 'WebApp.Security.Public' : 'WebApp.Security.Private',
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
			$stream = mapi_openproperty($assocMessage, PR_BODY, IID_IStream, 0, MAPI_CREATE | MAPI_MODIFY);
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
	 * Retrieve the GAB User.
	 *
	 * FIXME: ideally this would be a public function in WebApp.
	 *
	 * @param String $email the email address of the user
	 * @return Mixed $user Boolean if false else MAPIObject.
	 */
	function getGABUser($email)
	{
		$addrbook = $GLOBALS["mapisession"]->getAddressbook();
		$userArr = array( array( PR_DISPLAY_NAME => $email) );
		$user = False;

		try {
			$user = mapi_ab_resolvename($addrbook, $userArr, EMS_AB_ADDRESS_LOOKUP);
			$user = mapi_ab_openentry($addrbook, $user[0][PR_ENTRYID]);
		} catch (MAPIException $e) {
			$e->setHandled();
		}

		return $user;
	}

	/**
	 * Retrieve the PR_EMS_AB_TAGGED_X509_CERT
	 *
	 * @param MAPIObject $user the GAB user
	 * @return String $cert the certificate, empty if not found
	 */
	function getGABCert($user)
	{
		$cert = '';
		$userCertArray = mapi_getprops($user, array(PR_EMS_AB_TAGGED_X509_CERT));
		if (isset($userCertArray[PR_EMS_AB_TAGGED_X509_CERT])) {
			$cert = der2pem($userCertArray[PR_EMS_AB_TAGGED_X509_CERT][0]);
		}

		return $cert;
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
							'passphrase_cache' => PLUGIN_SMIME_PASSPHRASE_REMEMBER_BROWSER,
						)
					)
				)
			)
		));
	}

	/**
	 * Get sender structure of the MAPI Message.
	 *
	 * @param mapimessage $mapiMessage  MAPI Message resource from which we need to get the sender.
	 * @return array with properties
	 */
	function getSenderAddress($mapiMessage)
	{
		// WebApp will remove this method in the future (3.4.0)
		if (!method_exists($GLOBALS['operations'], 'getSenderAddress')) {
			$messageProps  = mapi_getprops($mapiMessage, array(PR_SENT_REPRESENTING_ENTRYID, PR_SENDER_ENTRYID));
			$senderEntryID = isset($messageProps[PR_SENT_REPRESENTING_ENTRYID])? $messageProps[PR_SENT_REPRESENTING_ENTRYID] : $messageProps[PR_SENDER_ENTRYID];
			$senderUser = mapi_ab_openentry($GLOBALS["mapisession"]->getAddressbook(), $senderEntryID);

			if ($senderUser) {
				$userprops = mapi_getprops($senderUser, array(PR_ADDRTYPE, PR_DISPLAY_NAME, PR_EMAIL_ADDRESS, PR_SMTP_ADDRESS, PR_OBJECT_TYPE,PR_RECIPIENT_TYPE, PR_DISPLAY_TYPE, PR_DISPLAY_TYPE_EX, PR_ENTRYID));

				$senderStructure = array();
				$senderStructure["props"]['entryid']         = bin2hex($userprops[PR_ENTRYID]);
				$senderStructure["props"]['display_name']    = isset($userprops[PR_DISPLAY_NAME]) ? $userprops[PR_DISPLAY_NAME] : '';
				$senderStructure["props"]['email_address']   = isset($userprops[PR_EMAIL_ADDRESS]) ? $userprops[PR_EMAIL_ADDRESS] : '';
				$senderStructure["props"]['smtp_address']    = isset($userprops[PR_SMTP_ADDRESS]) ? $userprops[PR_SMTP_ADDRESS] : '';
				$senderStructure["props"]['address_type']    = isset($userprops[PR_ADDRTYPE]) ? $userprops[PR_ADDRTYPE] : '';
				$senderStructure["props"]['object_type']     = $userprops[PR_OBJECT_TYPE];
				$senderStructure["props"]['recipient_type']  = MAPI_TO;
				$senderStructure["props"]['display_type']    = isset($userprops[PR_DISPLAY_TYPE])    ? $userprops[PR_DISPLAY_TYPE]    : MAPI_MAILUSER;
				$senderStructure["props"]['display_type_ex'] = isset($userprops[PR_DISPLAY_TYPE_EX]) ? $userprops[PR_DISPLAY_TYPE_EX] : MAPI_MAILUSER;
			}
			return $senderStructure;
		} else {
			return $GLOBALS["operations"]->getSenderAddress($mapiMessage);
		}
	}

	/**
	 * Function which is used to remove duplicate recipients.
	 * While we decrypt an encrypted message some how mapi will append the recipients instead of replace.
	 * So to handle this situation by removing duplicate recipients from message.
	 * @param object $message  MAPI Message object from which we need to get the recipients.
         *
         * FIXME: Remove when KC-419 is resolved.
	 */
	function removeDuplicateRecipients($message)
	{
            $recipientTable = mapi_message_getrecipienttable($message);
            if (!$recipientTable) {
                return;
            }

            $recipients = mapi_table_queryallrows($recipientTable, $GLOBALS['properties']->getRecipientProperties());
            $removeRecipients = array();
            $tmp = array();

            foreach ($recipients as $recipient) {
                $entryid = $recipient[PR_ENTRYID];

                if (array_key_exists($entryid, $tmp)) {
                    // Duplicate, remove it.
                    array_push($removeRecipients, $recipient);
                } else {
                    $tmp[$entryid] = True;
                }
            }

            if (!empty($removeRecipients)) {
                mapi_message_modifyrecipients($message, MODRECIP_REMOVE, $removeRecipients);
            }
	}
}
?>
