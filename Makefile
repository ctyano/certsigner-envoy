ifeq ($(APP_NAME),)
APP_NAME := $(shell basename $(shell pwd))
endif

ifeq ($(DOCKER_TAG),)
DOCKER_TAG := :latest
endif
ifneq ($(VERSION),)
DOCKER_TAG := :v$(VERSION)
endif
ifeq ($(ENVOY_VERSION),)
ENVOY_VERSION := $(shell curl -s https://api.github.com/repos/envoyproxy/envoy/releases | jq -r .[].tag_name | sort -rV | head -n1)
ifeq ($(ENVOY_VERSION),)
$(error Failed to determine ENVOY_VERSION from GitHub API. Please set it manually.)
endif
endif

ifeq ($(PATCH),)
PATCH := true
endif

ifeq ($(PUSH),)
PUSH := true
endif
ifeq ($(PUSH),true)
PUSH_OPTION := --push
endif

BUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
VCS_REF=$(shell cd $(SUBMODULE_NAME) && git rev-parse --short HEAD)

ifeq ($(XPLATFORMS),)
XPLATFORMS := linux/amd64,linux/arm64
endif
XPLATFORM_ARGS := --platform=$(XPLATFORMS)

BUILD_ARG := --build-arg 'BUILD_DATE=$(BUILD_DATE)' --build-arg 'VCS_REF=$(VCS_REF)' --build-arg 'VERSION=$(VERSION)' --build-arg 'ENVOY_VERSION=$(ENVOY_VERSION)'

ifeq ($(DOCKER_REGISTRY_OWNER),)
DOCKER_REGISTRY_OWNER=ctyano
endif

ifeq ($(DOCKER_REGISTRY),)
DOCKER_REGISTRY=ghcr.io/$(DOCKER_REGISTRY_OWNER)/
endif

ifeq ($(DOCKER_CACHE),)
DOCKER_CACHE=false
endif

.PHONY: buildx

.SILENT: version

build:
	IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME)$(DOCKER_TAG); \
	LATEST_IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME):latest; \
	DOCKERFILE_PATH=./Dockerfile; \
	test $(DOCKER_CACHE) && DOCKER_CACHE_OPTION="--cache-from $$IMAGE_NAME"; \
	docker build $(BUILD_ARG) $$DOCKER_CACHE_OPTION -t $$IMAGE_NAME -t $$LATEST_IMAGE_NAME -f $$DOCKERFILE_PATH .

buildx:
	IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME)$(DOCKER_TAG); \
	LATEST_IMAGE_NAME=$(DOCKER_REGISTRY)$(APP_NAME):latest; \
	DOCKERFILE_PATH=./Dockerfile; \
	DOCKER_BUILDKIT=1 docker buildx build $(BUILD_ARG) $(XPLATFORM_ARGS) $(PUSH_OPTION) --cache-from $$IMAGE_NAME -t $$IMAGE_NAME -t $$LATEST_IMAGE_NAME -f $$DOCKERFILE_PATH .

mirror-amd64-images:
	IMAGE=$(APP_NAME); docker pull --platform linux/amd64 ghcr.io/ctyano/$$IMAGE:latest && docker tag ghcr.io/ctyano/$$IMAGE:latest docker.io/tatyano/$$IMAGE:latest && docker push docker.io/tatyano/$$IMAGE:latest

install-golang:
	which go \
|| (curl -sf https://webi.sh/golang | sh \
&& ~/.local/bin/pathman add ~/.local/bin)

patch:
	$(PATCH) && rsync -av --exclude=".gitkeep" patchfiles/* $(SUBMODULE_NAME)

clean: #checkout

diff:
	@diff $(SUBMODULE_NAME) patchfiles

checkout:
	@cd $(SUBMODULE_NAME)/ && git checkout .

submodule-update: checkout
	@git submodule update --init --remote

checkout-version: submodule-update
	@cd $(SUBMODULE_NAME)/ && git fetch --refetch --tags origin && git checkout v$(VERSION)

version:
	@echo "Version: $(VERSION)"
	@echo "Tag Version: v$(VERSION)"

install-pathman:
	test -e ~/.local/bin/pathman \
|| curl -sf https://webi.sh/pathman | sh

install-jq: install-pathman
	which jq \
|| (curl -sf https://webi.sh/jq | sh \
&& ~/.local/bin/pathman add ~/.local/bin)

install-yq: install-pathman
	which yq \
|| (curl -sf https://webi.sh/yq | sh \
&& ~/.local/bin/pathman add ~/.local/bin)

install-step: install-pathman
	which step \
|| (STEP_VERSION=$$(curl -sf https://api.github.com/repos/smallstep/cli/releases | jq -r .[].tag_name | grep -E '^v[0-9]*.[0-9]*.[0-9]*$$' | head -n1 | sed -e 's/.*v\([0-9]*.[0-9]*.[0-9]*\).*/\1/g') \
; curl -fL "https://github.com/smallstep/cli/releases/download/v$${STEP_VERSION}/step_$(GOOS)_$${STEP_VERSION}_$(GOARCH).tar.gz" | tar -xz -C ~/.local/bin/ \
&& ln -sf ~/.local/bin/step_$${STEP_VERSION}/bin/step ~/.local/bin/step \
&& ~/.local/bin/pathman add ~/.local/bin)

install-kustomize: install-pathman
	which kustomize \
|| (cd ~/.local/bin \
&& curl "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash \
&& ~/.local/bin/pathman add ~/.local/bin)

install-parsers: install-jq install-yq install-step

load-docker-images:
	docker pull docker.io/ghostunnel/ghostunnel:latest
	docker pull $(DOCKER_REGISTRY)crypki-softhsm:latest
	docker pull $(DOCKER_REGISTRY)athenz_user_cert:latest
	docker pull docker.io/ealen/echo-server:latest
	docker pull docker.io/dexidp/dex:latest

load-kubernetes-images:
	kubectl config get-contexts kind-kind --no-headers=true | grep -E "^\* +kind-kind"
	kind load docker-image \
		docker.io/ghostunnel/ghostunnel:latest \
		$(DOCKER_REGISTRY)crypki-softhsm:latest \
		$(DOCKER_REGISTRY)$(APP_NAME):latest \
		$(DOCKER_REGISTRY)athenz_user_cert:latest \
		docker.io/ealen/echo-server:latest \
		docker.io/dexidp/dex:latest

deploy-kubernetes-manifests: generate-certificates copy-certificates-to-kustomization
	kubectl apply -k kustomize

test-kubernetes-crypki-softhsm:
	SLEEP_SECONDS=5; \
WAITING_THRESHOLD=60; \
i=0; \
while true; do \
	printf "\n***** Waiting for crypki($$(( $$i * $${SLEEP_SECONDS} ))s/$${WAITING_THRESHOLD}s) *****\n"; \
	( \
	test $$(( $$(kubectl -n certsigner get all | grep certsigner-envoy | grep -E "0/1" | wc -l) )) -eq 0 \
	&& \
	kubectl -n certsigner exec deployment/certsigner-envoy -it -c athenz-cli -- \
		curl \
			-s \
			--fail \
			--cert \
			/opt/crypki/tls-crt/client.crt \
			--key \
			/opt/crypki/tls-crt/client.key \
			--cacert \
			/opt/crypki/tls-crt/ca.crt \
			--resolve \
			localhost:4443:127.0.0.1 \
			https://localhost:4443/ruok \
	) \
	&& break \
	|| echo "Waiting for Crypki SoftHSM Server..."; \
	sleep $${SLEEP_SECONDS}; \
	i=$$(( i + 1 )); \
	if [ $$i -eq $$(( $${WAITING_THRESHOLD} / $${SLEEP_SECONDS} )) ]; then \
		printf "\n\n** Waiting ($$(( $$i * $${SLEEP_SECONDS} ))s) reached to threshold($${WAITING_THRESHOLD}s) **\n\n"; \
		kubectl -n certsigner get all | grep -E "pod/certsigner-envoy-" | sed -e 's/^\(pod\/[^ ]*\) *[0-9]\/[0-9].*/\1/g' | xargs -I%% kubectl -n certsigner logs %% --all-containers=true ||:; \
		kubectl -n certsigner get all | grep -E "pod/certsigner-envoy-" | sed -e 's/^\(pod\/[^ ]*\) *[0-9]\/[0-9].*/\1/g' | xargs -I%% kubectl -n certsigner describe %% ||:; \
		kubectl -n certsigner get all; \
		exit 1; \
	fi; \
done
	kubectl -n certsigner get all
	@echo ""
	@echo "**************************************"
	@echo "***  Crypki provisioning successful **"
	@echo "**************************************"
	@echo ""

test-kubernetes-athenz-oauth2:
	timeout -k 0 30 kubectl -n certsigner port-forward deployment/certsigner-envoy 5556:5556 &
	timeout -k 0 30 kubectl -n certsigner port-forward deployment/certsigner-envoy 10000:10000 &
	SLEEP_SECONDS=5; \
WAITING_THRESHOLD=30; \
i=0; \
while true; do \
	printf "\n***** Waiting for athenz($$(( $$i * $${SLEEP_SECONDS} ))s/$${WAITING_THRESHOLD}s) *****\n"; \
	( \
	test $$(( $$(kubectl -n certsigner get all | grep certsigner-envoy | grep -E "0/1" | wc -l) )) -eq 0 \
	&& \
	kubectl -n certsigner exec deployment/certsigner-envoy -it -c dex -- \
	    nc -vz 127.0.0.1 5556 \
	&& \
	kubectl -n certsigner exec deployment/certsigner-envoy -it -c dex -- \
	    nc -vz 127.0.0.1 10000 \
	&& \
	kubectl -n certsigner exec deployment/certsigner-envoy -it -c athenz-user-cert  -- \
		athenz_user_cert test \
	) \
	&& break \
	|| echo "Waiting for Dex Identity Provider and Envoy CertSigner Proxy..."; \
	sleep $${SLEEP_SECONDS}; \
	i=$$(( i + 1 )); \
	if [ $$i -eq $$(( $${WAITING_THRESHOLD} / $${SLEEP_SECONDS} )) ]; then \
		printf "\n\n** Waiting ($$(( $$i * $${SLEEP_SECONDS} ))s) reached to threshold($${WAITING_THRESHOLD}s) **\n\n"; \
		kubectl -n certsigner get all | grep -E "pod/certsigner-envoy-" | sed -e 's/^\(pod\/[^ ]*\) *[0-9]\/[0-9].*/\1/g' | xargs -I%% kubectl -n certsigner logs %% --all-containers=true ||:; \
		kubectl -n certsigner get all | grep -E "pod/certsigner-envoy-" | sed -e 's/^\(pod\/[^ ]*\) *[0-9]\/[0-9].*/\1/g' | xargs -I%% kubectl -n certsigner describe %% ||:; \
		kubectl -n certsigner get all; \
		exit 1; \
	fi; \
done
	kubectl -n certsigner get all
	@echo ""
	@echo "**************************************"
	@echo "**** Oauth2 deployment successful ****"
	@echo "**************************************"
	@echo ""

clean-certificates:
	rm -rf keys certs

generate-ca:
	mkdir keys certs ||:
	openssl genrsa -out keys/ca.private.pem 4096
	openssl rsa -pubout -in keys/ca.private.pem -out keys/ca.public.pem
	openssl req -new -x509 -days 99999 -config openssl/ca.openssl.config -extensions ext_req -key keys/ca.private.pem -out certs/ca.cert.pem

generate-admin: generate-ca
	mkdir keys certs ||:
	openssl genrsa -out keys/athenz_admin.private.pem 4096
	openssl rsa -pubout -in keys/athenz_admin.private.pem -out keys/athenz_admin.public.pem
	openssl req -config openssl/athenz_admin.openssl.config -new -key keys/athenz_admin.private.pem -out certs/athenz_admin.csr.pem -extensions ext_req
	openssl x509 -req -in certs/athenz_admin.csr.pem -CA certs/ca.cert.pem -CAkey keys/ca.private.pem -CAcreateserial -out certs/athenz_admin.cert.pem -days 99999 -extfile openssl/athenz_admin.openssl.config -extensions ext_req
	openssl verify -CAfile certs/ca.cert.pem certs/athenz_admin.cert.pem

generate-crypki: generate-ca
	mkdir keys certs ||:
	openssl genrsa -out - 4096 | openssl pkey -out keys/crypki.private.pem
	openssl req -config openssl/crypki.openssl.config -new -key keys/crypki.private.pem -out certs/crypki.csr.pem -extensions ext_req
	openssl x509 -req -in certs/crypki.csr.pem -CA certs/ca.cert.pem -CAkey keys/ca.private.pem -CAcreateserial -out certs/crypki.cert.pem -days 99999 -extfile openssl/crypki.openssl.config -extensions ext_req
	openssl verify -CAfile certs/ca.cert.pem certs/crypki.cert.pem

generate-certificates: generate-ca generate-crypki generate-admin

copy-certificates-to-kustomization:
	cp -r keys certs kustomize/

