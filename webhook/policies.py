from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class PolicyResult:
    allowed: bool
    reason: Optional[str] = None


PolicyFunc = Callable[[dict], PolicyResult]


# --- Individual policies ---

def check_no_root(pod_object: dict) -> PolicyResult:
    """Reject pods that run (or could run) as root UID 0."""
    spec = pod_object.get("spec", {})
    pod_sc = spec.get("securityContext", {})

    if pod_sc.get("runAsUser") == 0:
        return PolicyResult(False, "Pod-level securityContext.runAsUser is 0 (root)")
    if pod_sc.get("runAsNonRoot") is False:
        return PolicyResult(False, "Pod-level securityContext.runAsNonRoot is explicitly false")

    all_containers = spec.get("containers", []) + spec.get("initContainers", [])
    for container in all_containers:
        name = container.get("name", "<unnamed>")
        sc = container.get("securityContext", {})
        if sc.get("runAsUser") == 0:
            return PolicyResult(False, f"Container '{name}' has runAsUser=0 (root)")
        if sc.get("runAsNonRoot") is False:
            return PolicyResult(False, f"Container '{name}' has runAsNonRoot=false")

    return PolicyResult(True)


def check_no_privileged(pod_object: dict) -> PolicyResult:
    """Reject pods with any container in privileged mode."""
    spec = pod_object.get("spec", {})
    all_containers = spec.get("containers", []) + spec.get("initContainers", [])
    for container in all_containers:
        name = container.get("name", "<unnamed>")
        sc = container.get("securityContext", {})
        if sc.get("privileged") is True:
            return PolicyResult(False, f"Container '{name}' runs in privileged mode")
    return PolicyResult(True)


def check_no_host_network(pod_object: dict) -> PolicyResult:
    """Reject pods using the host's network namespace."""
    if pod_object.get("spec", {}).get("hostNetwork") is True:
        return PolicyResult(False, "Pod uses hostNetwork=true (shares node network namespace)")
    return PolicyResult(True)


def check_no_host_pid(pod_object: dict) -> PolicyResult:
    """Reject pods using the host's PID namespace."""
    if pod_object.get("spec", {}).get("hostPID") is True:
        return PolicyResult(False, "Pod uses hostPID=true (shares node PID namespace)")
    return PolicyResult(True)


def check_resource_limits(pod_object: dict) -> PolicyResult:
    """Require all containers to declare CPU and memory limits."""
    spec = pod_object.get("spec", {})
    all_containers = spec.get("containers", []) + spec.get("initContainers", [])
    for container in all_containers:
        name = container.get("name", "<unnamed>")
        limits = container.get("resources", {}).get("limits", {})
        if "cpu" not in limits or "memory" not in limits:
            return PolicyResult(
                False,
                f"Container '{name}' missing resource limits (cpu and memory both required)",
            )
    return PolicyResult(True)


ALLOWED_REGISTRY_PREFIXES = ("docker.io/", "gcr.io/", "registry.k8s.io/", "quay.io/")


def check_image_registry(pod_object: dict) -> PolicyResult:
    """Reject pods using images from registries not in the allowlist."""
    spec = pod_object.get("spec", {})
    all_containers = spec.get("containers", []) + spec.get("initContainers", [])
    for container in all_containers:
        name = container.get("name", "<unnamed>")
        image = container.get("image", "")

        
        first_slash = image.find("/")
        if first_slash == -1:
            continue

        
        registry_candidate = image[:first_slash]
        looks_like_registry = "." in registry_candidate or ":" in registry_candidate

        if looks_like_registry:
            if not any(image.startswith(p) for p in ALLOWED_REGISTRY_PREFIXES):
                return PolicyResult(
                    False,
                    f"Container '{name}' image '{image}' uses non-allowed registry "
                    f"(allowed: {', '.join(ALLOWED_REGISTRY_PREFIXES)})",
                )
        

    return PolicyResult(True)




ACTIVE_POLICIES: list[tuple[str, PolicyFunc]] = [
    ("no-root", check_no_root),
    ("no-privileged", check_no_privileged),
    ("no-host-network", check_no_host_network),
    ("no-host-pid", check_no_host_pid),
    ("resource-limits-required", check_resource_limits),
    ("image-registry-allowlist", check_image_registry),
]


def evaluate_policies(pod_object: dict) -> PolicyResult:
    """Run all active policies. Return the first denial, or success if all pass."""
    for name, policy in ACTIVE_POLICIES:
        result = policy(pod_object)
        if not result.allowed:
            return PolicyResult(
                allowed=False,
                reason=f"[{name}] {result.reason}",
            )
    return PolicyResult(allowed=True, reason="All policies passed")
