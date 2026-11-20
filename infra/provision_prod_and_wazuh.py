#!/usr/bin/env python3
"""
infra/provision_prod_and_wazuh.py

Provisions the isolated Production/Target VCN (prod-vcn, 10.0.0.0/16), peers it with
security-vcn (172.16.0.0/16) via Local Peering Gateways (LPG), launches the Always Free
web-server (VM.Standard.E2.1.Micro) in prod-public-subnet (10.0.1.0/24), and launches
the Always Free wazuh-manager (VM.Standard.A1.Flex) in security-mgmt-subnet (172.16.1.0/24).

STRICT ALWAYS-FREE TIER ENFORCEMENT:
  - Compute shapes permitted: ONLY "VM.Standard.E2.1.Micro" and "VM.Standard.A1.Flex"
  - A1 OCPU limit: <= 4 OCPUs total, <= 24 GB RAM total
  - E2.1.Micro limit: <= 2 instances total
  - Boot volume limit: <= 200 GB total across tenancy
"""
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
import oci

ALLOWED_ALWAYS_FREE_SHAPES = {"VM.Standard.A1.Flex", "VM.Standard.E2.1.Micro"}

REPO_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = REPO_ROOT / "evidence" / "oci-phase2-prod-and-wazuh"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

PROFILE = os.environ.get("OCI_CLI_PROFILE", "soc-project")
CONFIG = oci.config.from_file(profile_name=PROFILE)
COMPARTMENT_ID = os.environ.get("OCI_COMPARTMENT_OCID", CONFIG["tenancy"])
PUB_KEY_PATH = Path(os.environ.get("PUBLIC_KEY_PATH", os.path.expanduser("~/.ssh/soc-automation-ed25519.pub")))
SSH_PUB_KEY = PUB_KEY_PATH.read_text(encoding="utf-8").strip()
TAGS = {"Project": "soc-automation", "Environment": "lab"}

iam = oci.identity.IdentityClient(CONFIG)
net = oci.core.VirtualNetworkClient(CONFIG)
compute = oci.core.ComputeClient(CONFIG)
bv = oci.core.BlockstorageClient(CONFIG)


def get_current_admin_cidr() -> str:
    override = os.environ.get("ADMIN_IP_CIDR", "").strip()
    if override and override != "0.0.0.0/0":
        return override
    for url in ("https://checkip.amazonaws.com", "https://ipv4.icanhazip.com", "https://api.ipify.org"):
        try:
            ip = urllib.request.urlopen(url, timeout=8).read().decode("utf-8").strip()
            if ip and "." in ip:
                return f"{ip}/32"
        except Exception:
            continue
    raise RuntimeError("Could not determine current public IPv4 address.")


def ensure_vcn(name: str, cidr: str, dns_label: str) -> oci.core.models.Vcn:
    existing = [v for v in net.list_vcns(COMPARTMENT_ID, display_name=name).data if v.lifecycle_state == "AVAILABLE"]
    if existing:
        vcn = existing[0]
        print(f"EXISTS  VCN {name}: {vcn.id} ({vcn.cidr_block})", flush=True)
    else:
        resp = net.create_vcn(oci.core.models.CreateVcnDetails(
            compartment_id=COMPARTMENT_ID,
            display_name=name,
            cidr_blocks=[cidr],
            dns_label=dns_label,
            freeform_tags=TAGS,
        ))
        vcn = oci.wait_until(net, net.get_vcn(resp.data.id), "lifecycle_state", "AVAILABLE").data
        print(f"CREATED VCN {name}: {vcn.id} ({cidr})", flush=True)

    # Clear VCN default security list so only NSGs govern traffic
    net.update_security_list(
        vcn.default_security_list_id,
        oci.core.models.UpdateSecurityListDetails(ingress_security_rules=[], egress_security_rules=[]),
    )
    return vcn


def ensure_igw(name: str, vcn_id: str) -> str:
    existing = [g for g in net.list_internet_gateways(COMPARTMENT_ID, vcn_id=vcn_id, display_name=name).data if g.lifecycle_state == "AVAILABLE"]
    if existing:
        print(f"EXISTS  IGW {name}: {existing[0].id}", flush=True)
        return existing[0].id
    resp = net.create_internet_gateway(oci.core.models.CreateInternetGatewayDetails(
        compartment_id=COMPARTMENT_ID,
        vcn_id=vcn_id,
        display_name=name,
        is_enabled=True,
        freeform_tags=TAGS,
    ))
    igw = oci.wait_until(net, net.get_internet_gateway(resp.data.id), "lifecycle_state", "AVAILABLE").data
    print(f"CREATED IGW {name}: {igw.id}", flush=True)
    return igw.id


def ensure_lpg(name: str, vcn_id: str) -> oci.core.models.LocalPeeringGateway:
    existing = [l for l in net.list_local_peering_gateways(COMPARTMENT_ID, vcn_id=vcn_id).data if l.display_name == name and l.lifecycle_state == "AVAILABLE"]
    if existing:
        print(f"EXISTS  LPG {name}: {existing[0].id} (status: {existing[0].peering_status})", flush=True)
        return existing[0]
    resp = net.create_local_peering_gateway(oci.core.models.CreateLocalPeeringGatewayDetails(
        compartment_id=COMPARTMENT_ID,
        vcn_id=vcn_id,
        display_name=name,
        freeform_tags=TAGS,
    ))
    lpg = oci.wait_until(net, net.get_local_peering_gateway(resp.data.id), "lifecycle_state", "AVAILABLE").data
    print(f"CREATED LPG {name}: {lpg.id}", flush=True)
    return lpg


def ensure_lpg_peering(prod_lpg: oci.core.models.LocalPeeringGateway, sec_lpg: oci.core.models.LocalPeeringGateway) -> None:
    fresh = net.get_local_peering_gateway(prod_lpg.id).data
    if fresh.peering_status == "PEERED":
        print(f"EXISTS  LPG Peering active (PEERED): {prod_lpg.id} <-> {sec_lpg.id}", flush=True)
        return
    print(f"CONNECTING LPGs: {prod_lpg.id} <-> {sec_lpg.id}...", flush=True)
    net.connect_local_peering_gateways(
        prod_lpg.id,
        oci.core.models.ConnectLocalPeeringGatewaysDetails(peer_id=sec_lpg.id),
    )
    for _ in range(15):
        st = net.get_local_peering_gateway(prod_lpg.id).data.peering_status
        if st == "PEERED":
            print(f"PEERED  LPGs successfully connected: {st}", flush=True)
            return
        time.sleep(2)


def ensure_route_table(name: str, vcn_id: str, rules: list[oci.core.models.RouteRule]) -> str:
    existing = [r for r in net.list_route_tables(COMPARTMENT_ID, vcn_id=vcn_id, display_name=name).data if r.lifecycle_state == "AVAILABLE"]
    if existing:
        rt_id = existing[0].id
        net.update_route_table(rt_id, oci.core.models.UpdateRouteTableDetails(route_rules=rules))
        print(f"UPDATED Route Table {name}: {rt_id}", flush=True)
        return rt_id
    resp = net.create_route_table(oci.core.models.CreateRouteTableDetails(
        compartment_id=COMPARTMENT_ID,
        vcn_id=vcn_id,
        display_name=name,
        route_rules=rules,
        freeform_tags=TAGS,
    ))
    rt = oci.wait_until(net, net.get_route_table(resp.data.id), "lifecycle_state", "AVAILABLE").data
    print(f"CREATED Route Table {name}: {rt.id}", flush=True)
    return rt.id


def ensure_subnet(name: str, vcn_id: str, cidr: str, dns_label: str, rt_id: str) -> str:
    existing = [s for s in net.list_subnets(COMPARTMENT_ID, vcn_id=vcn_id, display_name=name).data if s.lifecycle_state == "AVAILABLE"]
    if existing:
        sub_id = existing[0].id
        net.update_subnet(sub_id, oci.core.models.UpdateSubnetDetails(route_table_id=rt_id))
        print(f"EXISTS  Subnet {name}: {sub_id} ({cidr})", flush=True)
        return sub_id
    resp = net.create_subnet(oci.core.models.CreateSubnetDetails(
        compartment_id=COMPARTMENT_ID,
        vcn_id=vcn_id,
        display_name=name,
        cidr_block=cidr,
        dns_label=dns_label,
        route_table_id=rt_id,
        prohibit_public_ip_on_vnic=False,
        freeform_tags=TAGS,
    ))
    sub = oci.wait_until(net, net.get_subnet(resp.data.id), "lifecycle_state", "AVAILABLE").data
    print(f"CREATED Subnet {name}: {sub.id} ({cidr})", flush=True)
    return sub.id


def ensure_nsg_with_rules(name: str, vcn_id: str, desired_tcp_ingress: list[tuple[str, int, str]]) -> str:
    existing = [n for n in net.list_network_security_groups(compartment_id=COMPARTMENT_ID, vcn_id=vcn_id, display_name=name).data if n.lifecycle_state == "AVAILABLE"]
    if existing:
        nsg_id = existing[0].id
        print(f"EXISTS  NSG {name}: {nsg_id}", flush=True)
    else:
        resp = net.create_network_security_group(oci.core.models.CreateNetworkSecurityGroupDetails(
            compartment_id=COMPARTMENT_ID,
            vcn_id=vcn_id,
            display_name=name,
            freeform_tags=TAGS,
        ))
        nsg = oci.wait_until(net, net.get_network_security_group(resp.data.id), "lifecycle_state", "AVAILABLE").data
        nsg_id = nsg.id
        print(f"CREATED NSG {name}: {nsg_id}", flush=True)

    current_rules = net.list_network_security_group_security_rules(nsg_id).data
    if current_rules:
        net.remove_network_security_group_security_rules(
            nsg_id,
            oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(
                security_rule_ids=[r.id for r in current_rules]
            ),
        )

    add_rules = []
    for src_cidr, port, desc in desired_tcp_ingress:
        add_rules.append(oci.core.models.AddSecurityRuleDetails(
            direction="INGRESS",
            protocol="6",
            source=src_cidr,
            source_type="CIDR_BLOCK",
            is_stateless=False,
            description=desc,
            tcp_options=oci.core.models.TcpOptions(
                destination_port_range=oci.core.models.PortRange(min=port, max=port)
            ),
        ))
    add_rules.append(oci.core.models.AddSecurityRuleDetails(
        direction="EGRESS",
        protocol="all",
        destination="0.0.0.0/0",
        destination_type="CIDR_BLOCK",
        is_stateless=False,
        description="Allow all outbound traffic",
    ))
    net.add_network_security_group_security_rules(
        nsg_id,
        oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(security_rules=add_rules),
    )
    print(f"SYNCED  NSG {name} rules ({len(add_rules)} rules)", flush=True)
    return nsg_id


def resolve_ubuntu_image(shape: str, require_arm: bool) -> tuple[str, str]:
    for os_ver in ("24.04", "22.04"):
        imgs = oci.pagination.list_call_get_all_results(
            compute.list_images,
            COMPARTMENT_ID,
            operating_system="Canonical Ubuntu",
            operating_system_version=os_ver,
            shape=shape,
            sort_by="TIMECREATED",
            sort_order="DESC",
        ).data
        for img in imgs:
            dname = img.display_name or ""
            if "Minimal" in dname:
                continue
            if require_arm and "aarch64" in dname:
                return img.id, dname
            if not require_arm and "aarch64" not in dname:
                return img.id, dname
    raise RuntimeError(f"Could not find Canonical Ubuntu image for {shape}")


def main() -> int:
    admin_cidr = get_current_admin_cidr()
    ad_name = iam.list_availability_domains(COMPARTMENT_ID).data[0].name
    print(f"=== Pre-flight (Always Free Only) ===", flush=True)
    print(f"Region:              {CONFIG['region']}", flush=True)
    print(f"Availability Domain: {ad_name}", flush=True)
    print(f"Admin Public CIDR:   {admin_cidr}", flush=True)

    # 1. Ensure both VCNs (security-vcn 172.16.0.0/16 & prod-vcn 10.0.0.0/16)
    sec_vcn = ensure_vcn("security-vcn", "172.16.0.0/16", "securityvcn")
    prod_vcn = ensure_vcn("prod-vcn", "10.0.0.0/16", "prodvcn")

    # 2. Ensure IGWs & LPG Peering between prod-vcn and security-vcn
    sec_igw_id = ensure_igw("security-igw", sec_vcn.id)
    prod_igw_id = ensure_igw("prod-igw", prod_vcn.id)

    prod_lpg = ensure_lpg("prod-lpg", prod_vcn.id)
    sec_lpg = ensure_lpg("security-lpg", sec_vcn.id)
    ensure_lpg_peering(prod_lpg, sec_lpg)

    # 3. Ensure Route Tables with IGW + Cross-VCN LPG routes
    sec_rt_id = ensure_route_table("security-mgmt-rt", sec_vcn.id, [
        oci.core.models.RouteRule(destination="0.0.0.0/0", destination_type="CIDR_BLOCK", network_entity_id=sec_igw_id),
        oci.core.models.RouteRule(destination="10.0.0.0/16", destination_type="CIDR_BLOCK", network_entity_id=sec_lpg.id),
    ])
    prod_rt_id = ensure_route_table("prod-public-rt", prod_vcn.id, [
        oci.core.models.RouteRule(destination="0.0.0.0/0", destination_type="CIDR_BLOCK", network_entity_id=prod_igw_id),
        oci.core.models.RouteRule(destination="172.16.0.0/16", destination_type="CIDR_BLOCK", network_entity_id=prod_lpg.id),
    ])

    # 4. Ensure Subnets
    sec_subnet_id = ensure_subnet("security-mgmt-subnet", sec_vcn.id, "172.16.1.0/24", "secmgmt", sec_rt_id)
    prod_subnet_id = ensure_subnet("prod-public-subnet", prod_vcn.id, "10.0.1.0/24", "prodpub", prod_rt_id)

    # 5. Ensure NSGs
    sec_nsg_id = ensure_nsg_with_rules("security-nsg", sec_vcn.id, [
        (admin_cidr, 22, "SSH (TCP 22) from admin public IP /32 only"),
        ("172.16.0.0/16", 11434, "Ollama API (TCP 11434) internal to security-vcn only"),
        ("0.0.0.0/0", 1514, "Wazuh agent data (TCP 1514)"),
        ("0.0.0.0/0", 1515, "Wazuh agent registration (TCP 1515)"),
        (admin_cidr, 443, "Wazuh dashboard HTTPS (TCP 443) from admin public IP /32 only"),
        (admin_cidr, 55000, "Wazuh API (TCP 55000) from admin public IP /32 only"),
    ])
    prod_nsg_id = ensure_nsg_with_rules("prod-web-nsg", prod_vcn.id, [
        (admin_cidr, 22, "SSH (TCP 22) from admin public IP /32 only"),
        ("172.16.0.0/16", 22, "SSH (TCP 22) from security-vcn over LPG"),
        ("0.0.0.0/0", 80, "HTTP (TCP 80) to web-server"),
        ("0.0.0.0/0", 443, "HTTPS (TCP 443) to web-server"),
    ])

    # 6. Launch Always Free web-server (VM.Standard.E2.1.Micro) in prod-public-subnet
    print("\n=== Launching Always Free Web Server (VM.Standard.E2.1.Micro) in prod-vcn ===", flush=True)
    web_existing = [i for i in compute.list_instances(COMPARTMENT_ID, display_name="web-server").data if i.lifecycle_state not in ("TERMINATED", "TERMINATING")]
    if web_existing:
        web_inst = web_existing[0]
        assert web_inst.shape in ALLOWED_ALWAYS_FREE_SHAPES, f"Unexpected shape {web_inst.shape}"
        print(f"EXISTS  web-server: {web_inst.id} ({web_inst.shape}, {web_inst.lifecycle_state})", flush=True)
    else:
        micro_shape = "VM.Standard.E2.1.Micro"
        assert micro_shape in ALLOWED_ALWAYS_FREE_SHAPES
        micro_img_id, micro_img_name = resolve_ubuntu_image(micro_shape, require_arm=False)
        print(f"Using x86_64 image for {micro_shape}: {micro_img_name}", flush=True)
        resp = compute.launch_instance(oci.core.models.LaunchInstanceDetails(
            availability_domain=ad_name,
            compartment_id=COMPARTMENT_ID,
            display_name="web-server",
            shape=micro_shape,
            image_id=micro_img_id,
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=prod_subnet_id,
                nsg_ids=[prod_nsg_id],
                assign_public_ip=True,
            ),
            metadata={"ssh_authorized_keys": SSH_PUB_KEY},
            freeform_tags={**TAGS, "Role": "web"},
        ), retry_strategy=oci.retry.NoneRetryStrategy())
        web_inst = oci.wait_until(compute, compute.get_instance(resp.data.id), "lifecycle_state", "RUNNING", max_wait_seconds=300).data
        print(f"RUNNING web-server ({micro_shape}): {web_inst.id}", flush=True)

    web_vnic_att = compute.list_vnic_attachments(COMPARTMENT_ID, instance_id=web_inst.id).data[0]
    web_vnic = net.get_vnic(web_vnic_att.vnic_id).data
    print(f"  web-server Private IP: {web_vnic.private_ip} | Public IP: {web_vnic.public_ip}", flush=True)

    # 7. Launch Always Free wazuh-manager (VM.Standard.A1.Flex) in security-mgmt-subnet
    print("\n=== Launching Always Free Wazuh Manager (VM.Standard.A1.Flex) in security-vcn ===", flush=True)
    wazuh_existing = [i for i in compute.list_instances(COMPARTMENT_ID, display_name="wazuh-manager").data if i.lifecycle_state not in ("TERMINATED", "TERMINATING")]
    if wazuh_existing:
        wazuh_inst = wazuh_existing[0]
        assert wazuh_inst.shape in ALLOWED_ALWAYS_FREE_SHAPES, f"Unexpected shape {wazuh_inst.shape}"
        print(f"EXISTS  wazuh-manager: {wazuh_inst.id} ({wazuh_inst.shape}, {wazuh_inst.lifecycle_state})", flush=True)
    else:
        a1_shape = "VM.Standard.A1.Flex"
        assert a1_shape in ALLOWED_ALWAYS_FREE_SHAPES
        a1_img_id, a1_img_name = resolve_ubuntu_image(a1_shape, require_arm=True)
        print(f"Using ARM64 image for {a1_shape}: {a1_img_name}", flush=True)
        wazuh_inst = None
        for ocpus, mem_gb, fd in [
            (2.0, 12.0, None),
        ]:
            fd_label = fd or "AUTO-FD"
            print(f"Trying Always Free {a1_shape} ({ocpus} OCPU / {mem_gb} GB, {fd_label})...", flush=True)
            try:
                resp = compute.launch_instance(oci.core.models.LaunchInstanceDetails(
                    availability_domain=ad_name,
                    fault_domain=fd,
                    compartment_id=COMPARTMENT_ID,
                    display_name="wazuh-manager",
                    shape=a1_shape,
                    shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(ocpus=ocpus, memory_in_gbs=mem_gb),
                    image_id=a1_img_id,
                    create_vnic_details=oci.core.models.CreateVnicDetails(
                        subnet_id=sec_subnet_id,
                        nsg_ids=[sec_nsg_id],
                        assign_public_ip=True,
                        private_ip="172.16.1.10",
                    ),
                    metadata={"ssh_authorized_keys": SSH_PUB_KEY},
                    freeform_tags={**TAGS, "Role": "wazuh"},
                ), retry_strategy=oci.retry.NoneRetryStrategy())
                wazuh_inst = oci.wait_until(compute, compute.get_instance(resp.data.id), "lifecycle_state", "RUNNING", max_wait_seconds=300).data
                print(f"RUNNING wazuh-manager ({a1_shape}): {wazuh_inst.id}", flush=True)
                break
            except oci.exceptions.ServiceError as exc:
                print(f"  -> {exc.status} {exc.code}: {exc.message}", flush=True)
                time.sleep(65)

        if wazuh_inst is None:
            print("\nNOTE: Always Free VM.Standard.A1.Flex (2 OCPU / 12 GB RAM) is currently out of host capacity in ap-mumbai-1.", flush=True)
            print("Run 'RETRY_UNTIL_CAPACITY=true bash infra/instances.sh' to poll until Oracle allocates the A1 instances.", flush=True)
            return 2

    wazuh_vnic_att = compute.list_vnic_attachments(COMPARTMENT_ID, instance_id=wazuh_inst.id).data[0]
    wazuh_vnic = net.get_vnic(wazuh_vnic_att.vnic_id).data
    print(f"  wazuh-manager Private IP: {wazuh_vnic.private_ip} | Public IP: {wazuh_vnic.public_ip}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
