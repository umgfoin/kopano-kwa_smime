# S/MIME Plugin

## Dependencies

* php-bcmath
* php-openssl
* php-curl
* php-kopano-smime (for PHP < 7.2)

## Tests

Run the basic unit tests. (requires libfaketime)

	make test

Coverage is located in htmlcov or can be viewed using

	make open-coverage

## Linting

S/MIME uses eslint, simply run the following command for linting.

	make lint

## S/MIME Certificate Storage

S/MIME Certificate private/public are stored in the users store in the root folder in the associated messages.
The private and public certificates are stored in a separate MAPI Message with the following properties set

Property                   | Content
-------------------------- | --------------------------------------------
PR_SUBJECT                 | Email address belonging to the certificate
PR_MESSAGE_CLASS           | WebApp.Security.Public or WebApp.Security.Private denotes certificate type
PR_MESSAGE_DELIVERY_TIME   | validTo time from the public certificate
PR_CLIENT_SUBMIT_TIME      | validFrom time from the public certificate
PR_SENDER_NAME             | The public certificate's serial number
PR_SENDER_EMAIL_ADDRESS    | The issuer denoted as C=NL ST=Zuid-Holland
PR_SUBJECT_PREFIX          | The subject denoted as C=NL .... CN=john
PR_RECEIVED_BY_NAME        | The SHA1 certificate finger print
PR_INTERNET_MESSAGE_ID     | The MD5 certificate finger print

In the attchment of this message the pkcs12 is stored (based64) encoded for a WebApp.Security.Private message,
   if it is a WebApp.Security.Public message the attachment contains a base64 encoded PEM file.

## Tools

The tools directory contains a tool to remove, list or import certificate in a user's store. For example:

	./tools/kopano-smime -u user1 --import test.12 --passphrase test
