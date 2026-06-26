CRD_OPTIONS ?= "crd:allowDangerousTypes=true"
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.19.0

.PHONY: manifests test

manifests:
	$(CONTROLLER_GEN) $(CRD_OPTIONS) paths="./apis/..." output:crd:artifacts:config=config/crd/bases

test:
	go test ./...
