# Tools

ANT ?= ant
PHPUNIT ?= phpunit
NPM ?= npm

# Build files

DEPLOY ?= deploy
PHPFILES = config.php $(wildcard php/*.php) $(wildcard php/*/*.php)
JSFILES = $(wildcard js/*.js) $(wildcard js/*/*.js)
RESOURCES = $(wildcard resources/css/*) $(wildcard resources/icons/*)
POFILES = $(wildcard language/*/LC_MESSAGES/*.po)

# Build

all: build

build: deploy

deploy: $(PHPFILES) $(JSFILES) $(RESOURCES) $(POFILES)
	# Ant doesn't update the deploy modification time
	touch $@
	$(ANT) deploy -Dplugin=smime -Dtarget-folder=$(DEPLOY)

# Test

.PHONY: test
test:
	$(PHPUNIT) -c unittest.xml

.PHONY: lint
lint: vendor
	eslint js

.PHONY: lintci
lintci: vendor
	eslint -f junit -o eslint.xml js || true

# NPM

.PHONY: vendor
vendor: node_modules

node_modules:
	$(NPM) install

.PHONY: clean
clean:
	@rm -rf deploy
	@rm -rf node_modules
