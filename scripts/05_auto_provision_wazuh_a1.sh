#!/usr/bin/env bash
#
# scripts/05_auto_provision_wazuh_a1.sh
#
# Continuously polls Oracle Cloud (ap-mumbai-1) for Always Free VM.Standard.A1.Flex
# (2 OCPUs / 12 GB RAM) capacity for wazuh-manager (172.16.1.10).
# As soon as capacity opens and the instance is RUNNING, it automatically:
#   1. Installs Wazuh Indexer + Wazuh Manager + Wazuh Dashboard (02_install_wazuh_stack.sh)
#   2. Connects web-server's Wazuh Agent over the VCN Local Peering Gateway (03_setup_web_and_wazuh_agent.sh)
#   3. Fires the WAF attack suite (test_web_attacks.py) so real alerts populate the Wazuh Dashboard
#   4. Retrieves the Wazuh Dashboard HTTPS URL and admin credentials.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${HOME}/.local/bin:${PATH}"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/soc-automation-ed25519}"
WEB_PUB_IP="${WEB_PUB_IP:-130.210.70.6}"

echo "=================================================================="
echo "  1. Waiting for OCI Always Free A1 Capacity (2 OCPU / 12 GB RAM)"
echo "=================================================================="

WAZUH_PUB_IP="$("${REPO_ROOT}/.venv/bin/python3" - "$REPO_ROOT" <<'PY'
import json
import os
import sys
import time
from pathlib import Path
import oci

SHAPE = "VM.Standard.A1.Flex"
OCPUS = 2.0
MEMORY_GB = 12.0
PRIVATE_IP = "172.16.1.10"

repo_root = Path(sys.argv[1])
evidence_dir = repo_root / "evidence" / "oci-phase1-security-network"
evidence_dir.mkdir(parents=True, exist_ok=True)

profile = os.environ.get("OCI_CLI_PROFILE", "soc-project")
config = oci.config.from_file(profile_name=profile)
comp = os.environ.get("OCI_COMPARTMENT_OCID", config["tenancy"])
ssh_pub_key = Path(os.path.expanduser("~/.ssh/soc-automation-ed25519.pub")).read_text(encoding="utf-8").strip()

iam = oci.identity.IdentityClient(config)
net = oci.core.VirtualNetworkClient(config)
compute = oci.core.ComputeClient(config)

ad_name = iam.list_availability_domains(comp).data[0].name
vcn = [v for v in net.list_vcns(comp, display_name="security-vcn").data if v.lifecycle_state == "AVAILABLE"][0]
sub = [s for s in net.list_subnets(comp, vcn_id=vcn.id, display_name="security-mgmt-subnet").data if s.lifecycle_state == "AVAILABLE"][0]
nsg = [n for n in net.list_network_security_groups(compartment_id=comp, vcn_id=vcn.id, display_name="security-nsg").data if n.lifecycle_state == "AVAILABLE"][0]

imgs = oci.pagination.list_call_get_all_results(
    compute.list_images,
    comp,
    operating_system="Canonical Ubuntu",
    operating_system_version="24.04",
    shape=SHAPE,
    sort_by="TIMECREATED",
    sort_order="DESC",
).data
arm_img = next(i for i in imgs if "aarch64" in (i.display_name or "") and "Minimal" not in (i.display_name or ""))

def get_public_ip(instance_id: str) -> str:
    atts = compute.list_vnic_attachments(comp, instance_id=instance_id).data
    for att in atts:
        if att.lifecycle_state == "ATTACHED":
            vnic = net.get_vnic(att.vnic_id).data
            if vnic.public_ip:
                return vnic.public_ip
    raise RuntimeError(f"No public IP found for instance {instance_id}")

existing = [
    i for i in compute.list_instances(comp, display_name="wazuh-manager").data
    if i.lifecycle_state not in ("TERMINATED", "TERMINATING")
]
if existing:
    inst = existing[0]
    if inst.shape != SHAPE:
        raise SystemExit(f"FATAL: Existing wazuh-manager has non-Always-Free shape {inst.shape}")
    if inst.lifecycle_state != "RUNNING":
        oci.wait_until(compute, compute.get_instance(inst.id), "lifecycle_state", "RUNNING", max_wait_seconds=300)
    pub_ip = get_public_ip(inst.id)
    print(f"[+] Existing wazuh-manager is RUNNING at {pub_ip}", file=sys.stderr, flush=True)
    print(pub_ip)
    raise SystemExit(0)

fds = ["FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"]
attempt = 0
while True:
    attempt += 1
    fd = fds[(attempt - 1) % len(fds)]
    print(f"[Attempt {attempt}] Requesting Always Free wazuh-manager ({SHAPE} 2 OCPU / 12 GB, {fd})...", file=sys.stderr, flush=True)
    details = oci.core.models.LaunchInstanceDetails(
        availability_domain=ad_name,
        fault_domain=fd,
        compartment_id=comp,
        display_name="wazuh-manager",
        shape=SHAPE,
        shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(ocpus=OCPUS, memory_in_gbs=MEMORY_GB),
        image_id=arm_img.id,
        create_vnic_details=oci.core.models.CreateVnicDetails(
            subnet_id=sub.id,
            nsg_ids=[nsg.id],
            assign_public_ip=True,
            private_ip=PRIVATE_IP,
        ),
        metadata={"ssh_authorized_keys": ssh_pub_key},
        freeform_tags={"Project": "soc-automation", "Environment": "lab", "Role": "wazuh"},
    )
    try:
        resp = compute.launch_instance(details, retry_strategy=oci.retry.NoneRetryStrategy())
        inst_id = resp.data.id
        print(f"[+] LAUNCHED wazuh-manager ({inst_id})! Waiting for RUNNING state...", file=sys.stderr, flush=True)
        oci.wait_until(compute, compute.get_instance(inst_id), "lifecycle_state", "RUNNING", max_wait_seconds=300)
        pub_ip = get_public_ip(inst_id)
        print(f"[+] wazuh-manager is RUNNING at Public IP: {pub_ip} (Private IP: {PRIVATE_IP})", file=sys.stderr, flush=True)
        print(pub_ip)
        raise SystemExit(0)
    except oci.exceptions.ServiceError as exc:
        print(f"    -> {exc.status} {exc.code}: {exc.message} (retrying in 65s)", file=sys.stderr, flush=True)
        time.sleep(65)
PY
)"

echo "[+] Acquired wazuh-manager Public IP: ${WAZUH_PUB_IP}"

echo "=================================================================="
echo "  2. Waiting for SSH Readiness on wazuh-manager (${WAZUH_PUB_IP})"
echo "=================================================================="
for i in $(seq 1 30); do
    if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "ubuntu@${WAZUH_PUB_IP}" "echo SSH_READY" >/dev/null 2>&1; then
        echo "[+] SSH is ready on ${WAZUH_PUB_IP}"
        break
    fi
    sleep 10
done

echo "=================================================================="
echo "  3. Installing Wazuh Indexer + Manager + Dashboard All-in-One"
echo "=================================================================="
bash "${REPO_ROOT}/scripts/02_install_wazuh_stack.sh" --remote "${WAZUH_PUB_IP}"

echo "=================================================================="
echo "  4. Verifying Web Server Agent Registration & Log Ingestion"
echo "=================================================================="
bash "${REPO_ROOT}/scripts/03_setup_web_and_wazuh_agent.sh" "${WEB_PUB_IP}" "${WAZUH_PUB_IP}" "172.16.1.10"

echo "=================================================================="
echo "  5. Firing WAF Attack Suite to Populate Wazuh Dashboard Alerts"
echo "=================================================================="
python3 "${REPO_ROOT}/scripts/test_web_attacks.py" --target "http://${WEB_PUB_IP}" --verify-logs

echo "=================================================================="
echo "  6. Wazuh Dashboard Access Details"
echo "=================================================================="
ADMIN_PASS=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@${WAZUH_PUB_IP}" \
    "sudo awk '/indexer_username: admin/ || /admin/ {getline; print}' /root/wazuh-passwords.txt 2>/dev/null | head -n 5 || sudo grep -A 2 'admin' /root/wazuh-passwords.txt 2>/dev/null || true")
echo "Wazuh Dashboard URL : https://${WAZUH_PUB_IP}"
echo "Username            : admin"
echo "Credentials excerpt :"
echo "${ADMIN_PASS}"
