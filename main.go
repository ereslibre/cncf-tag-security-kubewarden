package main

import (
	"os"
	"os/exec"
	"path/filepath"

	demo "github.com/saschagrunert/demo"
)

func main() {
	d := demo.New()
	d.Add(kwctlRun(), "kwctl", "kwctl")
	d.Add(policyServerRun(), "policy-server", "policy-server")
	d.Add(gatekeeperPolicyBuildAndRun(), "gatekeeper", "gatekeeper")
	d.Add(opaPolicyBuildAndRun(), "opa", "opa")
	d.Run()
}

func kwctlRun() *demo.Run {
	r := demo.NewRun(
		"Running policies with kwctl",
	)

	r.Setup(cleanupKwctl)
	r.Cleanup(cleanupKwctl)

	kwctl(r)

	return r
}

func kwctl(r *demo.Run) {
	r.Step(demo.S(
		"List policies",
	), demo.S("kwctl policies"))

	r.Step(demo.S(
		"Pull a policy",
	), demo.S("kwctl pull registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.1"))

	r.Step(demo.S(
		"List policies",
	), demo.S("kwctl policies"))

	r.Step(demo.S(
		"Inspect policy",
	), demo.S("kwctl inspect registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.1"))

	r.Step(demo.S(
		"Request with a letsencrypt-production issuer",
	), demo.S("bat test_data/production-ingress.json"))

	r.Step(demo.S(
		"Evaluate request with a letsencrypt-production issuer",
	), demo.S("kwctl -v run",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"--request-path test_data/production-ingress.json",
		"registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.1 | jq"))

	r.Step(demo.S(
		"Request with a letsencrypt-staging issuer",
	), demo.S("bat test_data/staging-ingress.json"))

	r.StepCanFail(demo.S(
		"Evaluate request with a letsencrypt-staging issuer",
	), demo.S("kwctl -v run",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"--request-path test_data/staging-ingress.json",
		"registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.1 | jq"))

	r.Step(demo.S(
		"kwctl options",
	), demo.S("kwctl --help"))

	r.Step(demo.S(
		"Report digest",
	), demo.S("kwctl digest registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.1"))

	r.Step(demo.S(
		"Rego built-in compatibility",
	), demo.S("kwctl --version"))
}

func policyServerRun() *demo.Run {
	r := demo.NewRun(
		"Running policies on the policy-server",
	)

	r.Setup(setupKubernetes)
	r.Cleanup(cleanupKubernetes)

	policyServer(r)

	return r
}

func policyServer(r *demo.Run) {
	r.Step(demo.S(
		"Pull a policy",
	), demo.S("kwctl pull registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.1"))

	r.Step(demo.S(
		"Generate Kubernetes manifest",
	), demo.S("kwctl scaffold manifest",
		"--title generated-policy",
		"--type ClusterAdmissionPolicy",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.1 | bat --language yaml",
	))

	r.Step(demo.S(
		"Apply Kubernetes manifest",
	), demo.S(
		"kwctl scaffold manifest",
		"--title generated-policy",
		"--type ClusterAdmissionPolicy",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.1 |",
		"kubectl apply -f -"))

	r.Step(demo.S(
		"Wait for our policy to be active",
	), demo.S(
		"kubectl wait --for=condition=PolicyActive clusteradmissionpolicy generated-policy",
	))

	r.Step(demo.S(
		"Ingress with a letsencrypt-production issuer",
	), demo.S("bat test_data/production-ingress-resource.yaml"))

	r.Step(demo.S(
		"Deploy an Ingress resource with a letsencrypt-production issuer",
	), demo.S("kubectl apply -f test_data/production-ingress-resource.yaml"))

	r.Step(demo.S(
		"Ingress with a letsencrypt-staging issuer",
	), demo.S("bat test_data/staging-ingress-resource.yaml"))

	r.StepCanFail(demo.S(
		"Deploy an Ingress resource with a letsencrypt-staging issuer",
	), demo.S("kubectl apply -f test_data/staging-ingress-resource.yaml"))
}

func gatekeeperPolicyBuildAndRun() *demo.Run {
	r := demo.NewRun(
		"Running a gatekeeper policy",
	)

	r.Step(demo.S(
		"Show policy",
	), demo.S("bat policies/gatekeeper/k8srequiredlabels.rego"))

	r.Step(demo.S(
		"Build policy",
	), demo.S(
		"opa build -t wasm -e k8srequiredlabels/violation -o policies/gatekeeper/bundle.tar.gz policies/gatekeeper/k8srequiredlabels.rego",
	))

	r.Step(demo.S(
		"Extract policy",
	), demo.S(
		"tar -C policies/gatekeeper -xf policies/gatekeeper/bundle.tar.gz /policy.wasm",
	))

	r.Step(demo.S(
		"Show a request that is valid -- contains an 'owner-team' key",
	), demo.S(
		"bat test_data/having-label-deployment.json",
	))

	r.Step(demo.S(
		"Run policy with a request that is valid",
	), demo.S(
		"kwctl run -e gatekeeper",
		`--settings-json '{"labels":[{"key":"owner-team"}]}'`,
		"--request-path test_data/having-label-deployment.json",
		"policies/gatekeeper/policy.wasm | jq",
	))

	r.Step(demo.S(
		"Show a request that is invalid -- does not contain an 'owner-team' key",
	), demo.S(
		"bat test_data/missing-label-deployment.json",
	))

	r.StepCanFail(demo.S(
		"Run policy with a request that is invalid",
	), demo.S(
		"kwctl run -e gatekeeper",
		`--settings-json '{"labels":[{"key":"owner-team"}]}'`,
		"--request-path test_data/missing-label-deployment.json",
		"policies/gatekeeper/policy.wasm | jq",
	))

	return r
}

func opaPolicyBuildAndRun() *demo.Run {
	r := demo.NewRun(
		"Running an Open Policy Agent policy",
	)
	r.Step(demo.S(
		"Show policy",
	), demo.S("bat policies/opa/utility/policy.rego policies/opa/k8srequiredlabels.rego"))
	r.Step(demo.S(
		"Build policy",
	), demo.S(
		"opa build -t wasm -e policy/main -o policies/opa/bundle.tar.gz policies/opa/utility/policy.rego policies/opa/k8srequiredlabels.rego",
	))

	r.Step(demo.S(
		"Extract policy",
	), demo.S(
		"tar -C policies/opa -xf policies/opa/bundle.tar.gz /policy.wasm",
	))

	r.Step(demo.S(
		"Show a request that is valid -- contains an 'owner-team' key",
	), demo.S(
		"bat test_data/having-label-deployment.json",
	))

	r.Step(demo.S(
		"Run policy with a request that is valid",
	), demo.S(
		"kwctl run -e opa",
		`--settings-json '{"labels":[{"key":"owner-team"}]}'`,
		"--request-path test_data/having-label-deployment.json",
		"policies/opa/policy.wasm | jq",
	))

	r.Step(demo.S(
		"Show a request that is invalid -- does not contain an 'owner-team' key",
	), demo.S(
		"bat test_data/missing-label-deployment.json",
	))

	r.StepCanFail(demo.S(
		"Run policy with a request that is invalid",
	), demo.S(
		"kwctl run -e opa",
		`--settings-json '{"labels":[{"key":"owner-team"}]}'`,
		"--request-path test_data/missing-label-deployment.json",
		"policies/opa/policy.wasm | jq",
	))

	return r
}

func cleanupKwctl() error {
	os.RemoveAll(filepath.Join(os.Getenv("HOME"), ".cache", "kubewarden"))
	return nil
}

func setupKubernetes() error {
	cleanupKwctl()
	cleanupKubernetes()
	exec.Command("kubectl", "create", "namespace", "cncf-tag-security-demo").Run()
	exec.Command("kubectl", "delete", "clusteradmissionpolicy", "--all").Run()
	return nil
}

func cleanupKubernetes() error {
	cleanupKwctl()
	exec.Command("kubectl", "delete", "namespace", "cncf-tag-security-demo").Run()
	exec.Command("kubectl", "delete", "clusteradmissionpolicy", "--all").Run()
	return nil
}
