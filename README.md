# S/MIME Plugin

## Dependencies

* php-bcmath
* php-openssl
* php-curl
* php-kopano-smime 

## Tests

Run the basic unit tests. (requires libfaketime)

	phpunit -c unittest.xml

Coverage.

	phpunit -c unittest.xml --coverage-html /tmp/report
