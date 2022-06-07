k8srequiredlabels.wasm: k8srequiredlabels.rego
	opa build -t wasm -e k8srequiredlabels/violation $<
	tar -xf bundle.tar.gz /policy.wasm
	kwctl annotate --metadata-path metadata.yaml --output-path $@ policy.wasm
	rm policy.wasm bundle.tar.gz
