k8srequiredlabels.wasm: k8srequiredlabels.rego
	opa build -t wasm -e k8srequiredlabels/violation $<
	tar -xf bundle.tar.gz /policy.wasm
	mv policy.wasm k8srequiredlabels.wasm
	rm bundle.tar.gz
