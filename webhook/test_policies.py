"""Unit tests for pod admission policies."""
import pytest

from policies import (
    check_no_root,
    check_no_privileged,
    check_no_host_network,
    check_no_host_pid,
    check_resource_limits,
    check_image_registry,
    evaluate_policies,
)


# --- Shared fixture ---

@pytest.fixture
def safe_pod():
    """A pod that passes all policies. Tests mutate copies to violate one rule at a time."""
    return {
        "spec": {
            "containers": [{
                "name": "app",
                "image": "docker.io/library/busybox:latest",
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 1000,
                },
                "resources": {
                    "limits": {"cpu": "100m", "memory": "64Mi"},
                    "requests": {"cpu": "50m", "memory": "32Mi"},
                },
            }]
        }
    }


# --- no-root ---

class TestNoRoot:
    def test_safe_pod_allowed(self, safe_pod):
        assert check_no_root(safe_pod).allowed is True

    def test_pod_level_runasuser_zero_denied(self, safe_pod):
        safe_pod["spec"]["securityContext"] = {"runAsUser": 0}
        result = check_no_root(safe_pod)
        assert result.allowed is False
        assert "Pod-level" in result.reason
        assert "runAsUser is 0" in result.reason

    def test_pod_level_runasnonroot_false_denied(self, safe_pod):
        safe_pod["spec"]["securityContext"] = {"runAsNonRoot": False}
        result = check_no_root(safe_pod)
        assert result.allowed is False
        assert "runAsNonRoot is explicitly false" in result.reason

    def test_container_runasuser_zero_denied(self, safe_pod):
        safe_pod["spec"]["containers"][0]["securityContext"]["runAsUser"] = 0
        result = check_no_root(safe_pod)
        assert result.allowed is False
        assert "Container 'app'" in result.reason

    def test_init_container_root_denied(self, safe_pod):
        safe_pod["spec"]["initContainers"] = [{
            "name": "init",
            "securityContext": {"runAsUser": 0},
        }]
        result = check_no_root(safe_pod)
        assert result.allowed is False
        assert "Container 'init'" in result.reason

    def test_empty_spec_allowed(self):
        """Pod with no securityContext fields — allowed by current strict-but-permissive policy."""
        assert check_no_root({"spec": {}}).allowed is True


# --- no-privileged ---

class TestNoPrivileged:
    def test_safe_pod_allowed(self, safe_pod):
        assert check_no_privileged(safe_pod).allowed is True

    def test_privileged_container_denied(self, safe_pod):
        safe_pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
        result = check_no_privileged(safe_pod)
        assert result.allowed is False
        assert "privileged mode" in result.reason

    def test_privileged_init_container_denied(self, safe_pod):
        safe_pod["spec"]["initContainers"] = [{
            "name": "init",
            "securityContext": {"privileged": True},
        }]
        result = check_no_privileged(safe_pod)
        assert result.allowed is False
        assert "Container 'init'" in result.reason


# --- no-host-network ---

class TestNoHostNetwork:
    def test_safe_pod_allowed(self, safe_pod):
        assert check_no_host_network(safe_pod).allowed is True

    def test_host_network_denied(self, safe_pod):
        safe_pod["spec"]["hostNetwork"] = True
        result = check_no_host_network(safe_pod)
        assert result.allowed is False
        assert "hostNetwork" in result.reason


# --- no-host-pid ---

class TestNoHostPid:
    def test_safe_pod_allowed(self, safe_pod):
        assert check_no_host_pid(safe_pod).allowed is True

    def test_host_pid_denied(self, safe_pod):
        safe_pod["spec"]["hostPID"] = True
        result = check_no_host_pid(safe_pod)
        assert result.allowed is False
        assert "hostPID" in result.reason


# --- resource-limits ---

class TestResourceLimits:
    def test_safe_pod_allowed(self, safe_pod):
        assert check_resource_limits(safe_pod).allowed is True

    def test_no_resources_block_denied(self, safe_pod):
        del safe_pod["spec"]["containers"][0]["resources"]
        result = check_resource_limits(safe_pod)
        assert result.allowed is False
        assert "resource limits" in result.reason

    def test_only_cpu_limit_denied(self, safe_pod):
        safe_pod["spec"]["containers"][0]["resources"]["limits"] = {"cpu": "100m"}
        assert check_resource_limits(safe_pod).allowed is False

    def test_only_memory_limit_denied(self, safe_pod):
        safe_pod["spec"]["containers"][0]["resources"]["limits"] = {"memory": "64Mi"}
        assert check_resource_limits(safe_pod).allowed is False


# --- image-registry ---

class TestImageRegistry:
    @pytest.mark.parametrize("image", [
        "nginx",
        "library/nginx",
        "nginx:latest",
        "docker.io/library/nginx",
        "gcr.io/myproject/myapp:v1",
        "quay.io/jetstack/cert-manager:v1.13",
        "registry.k8s.io/pause:3.9",
    ])
    def test_allowed_registries(self, safe_pod, image):
        safe_pod["spec"]["containers"][0]["image"] = image
        assert check_image_registry(safe_pod).allowed is True, \
            f"image {image} should be allowed"

    @pytest.mark.parametrize("image", [
        "evil.com/malware:latest",
        "attacker.example/payload",
        "localhost:5000/private",
    ])
    def test_denied_registries(self, safe_pod, image):
        safe_pod["spec"]["containers"][0]["image"] = image
        result = check_image_registry(safe_pod)
        assert result.allowed is False
        assert "non-allowed registry" in result.reason


# --- evaluate_policies (orchestrator) ---

class TestEvaluatePolicies:
    def test_safe_pod_passes_all(self, safe_pod):
        assert evaluate_policies(safe_pod).allowed is True

    def test_first_failure_short_circuits(self, safe_pod):
        # Violates BOTH no-root AND no-privileged. no-root runs first,
        # should fire first and short-circuit.
        safe_pod["spec"]["securityContext"] = {"runAsUser": 0}
        safe_pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
        result = evaluate_policies(safe_pod)
        assert result.allowed is False
        assert "[no-root]" in result.reason

    def test_failure_message_includes_policy_name(self, safe_pod):
        safe_pod["spec"]["hostNetwork"] = True
        result = evaluate_policies(safe_pod)
        assert result.allowed is False
        assert "[no-host-network]" in result.reason
