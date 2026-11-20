#!/usr/bin/env bash
#
# infra/instances.sh
#
# Phase 2 Oracle Cloud Infrastructure (OCI) Compute provisioning for the
# Security VCN Always Free Tier design (infra only, no software installed yet):
#   - ollama-server: VM.Standard.A1.Flex (2 OCPUs, 12 GB RAM, Ubuntu 24.04 aarch64)
#   - wazuh-manager: VM.Standard.A1.Flex (2 OCPUs, 12 GB RAM, Ubuntu 24.04 aarch64)
# Total: 4 OCPUs / 24 GB RAM (100% within Always Free Ampere A1 allowance).
#
# STRICT ALWAYS-FREE GUARD:
#   Only VM.Standard.A1.Flex (total <= 4 OCPUs / 24 GB RAM) and VM.Standard.E2.1.Micro
#   are permitted. Any non-Always-Free shape is strictly forbidden.
#
# Once both instances are RUNNING, this script automatically:
#   1. Saves real CLI JSON outputs to evidence/oci-phase1-security-network/
#   2. Updates ai_engine/dashboard/targets.yaml with the real A1 instance IPs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${HOME}/.local/bin:${PATH}"

"${REPO_ROOT}/.venv/bin/python3" - "$REPO_ROOT" <<'PY'
import json
import os
import subprocess
import sys
import time
from pathlib import Path
import oci

ALLOWED_ALWAYS_FREE_SHAPES = {"VM.Standard.A1.Flex", "VM.Standard.E2.1.Micro"}
SHAPE = "VM.Standard.A1.Flex"
OCPUS = 2.0
MEMORY_GB = 12.0
RETRY_UNTIL_CAPACITY = os.environ.get("RETRY_UNTIL_CAPACITY", "false").lower() in ("true", "1", "yes")
MAX_ATTEMPTS = int(os.environ.get("MAX_A1_ATTEMPTS", "60" if RETRY_UNTIL_CAPACITY else "3"))

if SHAPE not in ALLOWED_ALWAYS_FREE_SHAPES:
    raise SystemExit(f"FATAL: Shape {SHAPE} is not an Always Free Tier shape! Refusing to launch.")

repo_root = Path(sys.argv[1])
evidence_dir = repo_root / "evidence" / "oci-phase1-security-network"
evidence_dir.mkdir(parents=True, exist_ok=True)
targets_yaml_path = repo_root / "ai_engine" / "dashboard" / "targets.yaml"

profile = os.environ.get("OCI_CLI_PROFILE", "soc-project")
config = oci.config.from_file(profile_name=profile)
compartment_id = os.environ.get("OCI_COMPARTMENT_OCID", config["tenancy"])
pub_key_path = Path(os.environ.get("PUBLIC_KEY_PATH", os.path.expanduser("~/.ssh/soc-automation-ed25519.pub")))
ssh_pub_key = pub_key_path.read_text(encoding="utf-8").strip()

iam = oci.identity.IdentityClient(config)
net = oci.core.VirtualNetworkClient(config)
compute = oci.core.ComputeClient(config)

ad_name = iam.list_availability_domains(compartment_id).data[0].name
vcns = [v for v in net.list_vcns(compartment_id, display_name="security-vcn").data if v.lifecycle_state == "AVAILABLE"]
if not vcns:
    raise SystemExit("ERROR: security-vcn not found. Run infra/provision.sh first.")
vcn_id = vcns[0].id

subnets = [s for s in net.list_subnets(compartment_id, vcn_id=vcn_id, display_name="security-mgmt-subnet").data if s.lifecycle_state == "AVAILABLE"]
subnet_id = subnets[0].id

nsgs = [n for n in net.list_network_security_groups(compartment_id=compartment_id, vcn_id=vcn_id, display_name="security-nsg").data if n.lifecycle_state == "AVAILABLE"]
nsg_id = nsgs[0].id

imgs = oci.pagination.list_call_get_all_results(
    compute.list_images,
    compartment_id,
    operating_system="Canonical Ubuntu",
    operating_system_version="24.04",
    shape=SHAPE,
    sort_by="TIMECREATED",
    sort_order="DESC",
).data
arm_image_id = None
arm_image_name = None
for img in imgs:
    name = img.display_name or ""
    if "aarch64" in name and "24.04" in name and "Minimal" not in name:
        arm_image_id = img.id
        arm_image_name = name
        break

if not arm_image_id:
    raise SystemExit("ERROR: No Canonical Ubuntu 24.04 aarch64 image found for VM.Standard.A1.Flex")

print(f"Availability Domain: {ad_name}", flush=True)
print(f"VCN ID:              {vcn_id}", flush=True)
print(f"Subnet ID:           {subnet_id}", flush=True)
print(f"NSG ID:              {nsg_id}", flush=True)
print(f"ARM64 Image:         {arm_image_name} ({arm_image_id})", flush=True)

def ensure_a1_instance(name: str, role: str, private_ip: str) -> str:
    existing = [
        i for i in compute.list_instances(compartment_id, display_name=name).data
        if i.lifecycle_state not in ("TERMINATED", "TERMINATING")
    ]
    if existing:
        inst = existing[0]
        if inst.shape != "VM.Standard.A1.Flex":
            raise SystemExit(f"FATAL: Existing instance {name} ({inst.id}) has shape {inst.shape}, expected VM.Standard.A1.Flex (2 OCPU / 12 GB)!")
        print(f"EXISTS  {name}: {inst.id} ({inst.shape}, {inst.lifecycle_state})", flush=True)
        return inst.id

    fds = [None, "FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"]
    for attempt in range(1, MAX_ATTEMPTS + 1):
        fd = fds[(attempt - 1) % len(fds)]
        details = oci.core.models.LaunchInstanceDetails(
            availability_domain=ad_name,
            fault_domain=fd,
            compartment_id=compartment_id,
            display_name=name,
            shape=SHAPE,
            shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(ocpus=OCPUS, memory_in_gbs=MEMORY_GB),
            image_id=arm_image_id,
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=subnet_id,
                nsg_ids=[nsg_id],
                assign_public_ip=True,
                private_ip=private_ip,
            ),
            metadata={"ssh_authorized_keys": ssh_pub_key},
            freeform_tags={"Project": "soc-automation", "Environment": "lab", "Role": role},
        )
        fd_label = fd or "AUTO-FD"
        print(f"[Attempt {attempt}/{MAX_ATTEMPTS}] Launching Always Free {name} ({SHAPE}: {OCPUS} OCPU / {MEMORY_GB} GB, private_ip={private_ip}, {fd_label})...", flush=True)
        try:
            resp = compute.launch_instance(details, retry_strategy=oci.retry.NoneRetryStrategy())
            inst_id = resp.data.id
            print(f"LAUNCHED {name}: {inst_id} — waiting for RUNNING...", flush=True)
            oci.wait_until(compute, compute.get_instance(inst_id), "lifecycle_state", "RUNNING", max_wait_seconds=300)
            print(f"RUNNING  {name}: {inst_id}", flush=True)
            return inst_id
        except oci.exceptions.ServiceError as exc:
            print(f"  -> {exc.status} {exc.code}: {exc.message}", flush=True)
            if attempt < MAX_ATTEMPTS:
                print("  Waiting 65s before next Always Free A1 capacity attempt...", flush=True)
                time.sleep(65)

    raise SystemExit(f"ERROR: Always Free {SHAPE} is still out of host capacity in {ad_name} after {MAX_ATTEMPTS} attempts.")

wazuh_id = ensure_a1_instance("wazuh-manager", "wazuh", private_ip="172.16.1.10")
ollama_id = ensure_a1_instance("ollama-server", "ollama", private_ip="172.16.1.20")

oci_bin = str(repo_root / ".venv" / "bin" / "oci")
inst_list_out = subprocess.check_output([
    oci_bin, "--profile", profile, "compute", "instance", "list",
    "--compartment-id", compartment_id,
    "--query", 'data[?"lifecycle-state" != \'TERMINATED\'].{name:"display-name", state:"lifecycle-state", shape:"shape"}',
], text=True)
(evidence_dir / "instances-list.json").write_text(inst_list_out, encoding="utf-8")

ollama_vnics_out = subprocess.check_output([
    oci_bin, "--profile", profile, "compute", "instance", "list-vnics",
    "--instance-id", ollama_id,
], text=True)
(evidence_dir / "ollama-server-vnics.json").write_text(ollama_vnics_out, encoding="utf-8")

wazuh_vnics_out = subprocess.check_output([
    oci_bin, "--profile", profile, "compute", "instance", "list-vnics",
    "--instance-id", wazuh_id,
], text=True)
(evidence_dir / "wazuh-manager-vnics.json").write_text(wazuh_vnics_out, encoding="utf-8")

ollama_ip = json.loads(ollama_vnics_out)["data"][0]["public-ip"]
wazuh_ip = json.loads(wazuh_vnics_out)["data"][0]["public-ip"]

targets_yaml_path.write_text(f"""# Target infrastructure endpoints for SOC Observability Dashboard
# Updated with live OCI Always Free VM.Standard.A1.Flex instance IPs:
#   - wazuh-manager: {wazuh_ip}
#   - ollama-server: {ollama_ip}

targets:
  - name: wazuh_manager_1514
    type: tcp_port
    host: {wazuh_ip}
    port: 1514

  - name: wazuh_manager_55000
    type: tcp_port
    host: {wazuh_ip}
    port: 55000

  - name: ollama
    type: http
    host: {ollama_ip}
    port: 11434
    path: /api/tags
""", encoding="utf-8")

print(f"OLLAMA_INSTANCE_ID={ollama_id} (Public IP: {ollama_ip})", flush=True)
print(f"WAZUH_INSTANCE_ID={wazuh_id} (Public IP: {wazuh_ip})", flush=True)
PY
