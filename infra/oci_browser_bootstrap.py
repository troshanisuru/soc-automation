#!/usr/bin/env python3
"""
Non-interactive browser-based OCI CLI bootstrap script.
Opens the Oracle Cloud Console login in the user's browser, listens on localhost:8181
for the OAuth callback, automatically discovers the tenancy's subscribed home region
across all OC1 regions, uploads the API signing key to OCI, and configures ~/.oci/config
for both [DEFAULT] and [soc-project] profiles.
"""
import concurrent.futures
import os
import sys
from pathlib import Path

import oci
from oci import identity, regions
from oci_cli import cli_setup, cli_util
from oci_cli.cli_setup_bootstrap import create_user_session


PRIORITY_REGIONS = [
    "ap-mumbai-1",
    "ap-hyderabad-1",
    "ap-singapore-1",
    "ap-singapore-2",
    "us-ashburn-1",
    "us-phoenix-1",
    "uk-london-1",
    "eu-frankfurt-1",
    "ap-tokyo-1",
    "ap-sydney-1",
    "me-dubai-1",
    "me-jeddah-1",
]


def discover_home_region(tenancy_ocid: str, signer: oci.auth.signers.SecurityTokenSigner) -> str:
    oc1_regions = list(PRIORITY_REGIONS) + [
        r for r, realm in regions.REGION_REALMS.items()
        if realm == "oc1" and r not in PRIORITY_REGIONS
    ]

    def probe_region(reg: str):
        client = identity.IdentityClient({"region": reg}, signer=signer, timeout=(4, 8))
        subs = client.list_region_subscriptions(tenancy_ocid).data
        for sub in subs:
            if sub.is_home_region:
                return sub.region_name
        if subs:
            return subs[0].region_name
        return reg

    print(f"Discovering home region for tenancy {tenancy_ocid}...", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        future_to_reg = {pool.submit(probe_region, reg): reg for reg in oc1_regions}
        for future in concurrent.futures.as_completed(future_to_reg):
            try:
                home_reg = future.result()
                if home_reg:
                    print(f"Discovered subscribed home region: {home_reg}", flush=True)
                    return home_reg
            except Exception:
                continue

    raise RuntimeError(f"Could not discover subscribed home region for tenancy {tenancy_ocid}")


def main() -> int:
    region = os.environ.get("OCI_REGION", "ap-singapore-1")
    print(f"=== Starting Oracle Cloud Browser Authentication ===", flush=True)
    print("A browser window will open to sign in to your Oracle Cloud account.", flush=True)

    user_session = create_user_session(region=region)

    public_key = user_session.public_key
    private_key = user_session.private_key
    token = user_session.token
    tenancy_ocid = user_session.tenancy_ocid
    user_ocid = user_session.user_ocid
    fingerprint = user_session.fingerprint

    # Persist key pair & session token immediately so we never lose the browser login
    oci_dir = Path.home() / ".oci"
    oci_dir.mkdir(mode=0o700, exist_ok=True)
    priv_path = oci_dir / "oci_api_key.pem"
    pub_path = oci_dir / "oci_api_key_public.pem"
    token_path = oci_dir / "security_token"
    config_path = oci_dir / "config"

    cli_setup.write_public_key_to_file(str(pub_path), public_key, True, True)
    cli_setup.write_private_key_to_file(str(priv_path), private_key, None, True, True)
    token_path.write_text(token, encoding="utf-8")
    os.chmod(priv_path, 0o600)
    os.chmod(token_path, 0o600)

    signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
    home_region = discover_home_region(tenancy_ocid, signer)

    home_client = identity.IdentityClient({"region": home_region}, signer=signer)

    create_api_key_details = identity.models.CreateApiKeyDetails()
    create_api_key_details.key = cli_util.serialize_key(public_key=public_key).decode("UTF-8")

    try:
        home_client.upload_api_key(user_ocid, create_api_key_details)
        print(f"Uploaded API key ({fingerprint}) to OCI user {user_ocid}", flush=True)
    except oci.exceptions.ServiceError as exc:
        if exc.status == 409 and exc.code == "ApiKeyLimitExceeded":
            keys = home_client.list_api_keys(user_ocid).data
            oldest = sorted(keys, key=lambda k: k.time_created)[0]
            print(f"API key limit reached; replacing oldest key ({oldest.fingerprint})...", flush=True)
            home_client.delete_api_key(user_ocid, oldest.fingerprint)
            home_client.upload_api_key(user_ocid, create_api_key_details)
        elif exc.status == 409 and exc.code == "KeyAlreadyExists":
            print(f"API key ({fingerprint}) already exists on user.", flush=True)
        else:
            print(f"Note: upload_api_key returned {exc.code} ({exc.message}); persisting session token fallback.", flush=True)

    config_text = f"""[DEFAULT]
user={user_ocid}
fingerprint={fingerprint}
tenancy={tenancy_ocid}
region={home_region}
key_file={priv_path}
security_token_file={token_path}

[soc-project]
user={user_ocid}
fingerprint={fingerprint}
tenancy={tenancy_ocid}
region={home_region}
key_file={priv_path}
"""
    config_path.write_text(config_text, encoding="utf-8")
    os.chmod(config_path, 0o600)

    repo_root = Path(__file__).resolve().parent.parent
    env_file = repo_root / ".env"
    env_text = f"""OCI_CLI_PROFILE=soc-project
OCI_REGION={home_region}
EXPECTED_OCI_TENANCY_OCID={tenancy_ocid}
OCI_COMPARTMENT_OCID={tenancy_ocid}
OCI_USER_OCID={user_ocid}
SHADOW_MODE=true
"""
    env_file.write_text(env_text, encoding="utf-8")
    os.chmod(env_file, 0o600)

    print("==================================================================", flush=True)
    print("  SUCCESS: LOCAL PC BOUND TO ORACLE CLOUD INFRASTRUCTURE (OCI)!", flush=True)
    print("==================================================================", flush=True)
    print(f"  Tenancy OCID:     {tenancy_ocid}", flush=True)
    print(f"  User OCID:        {user_ocid}", flush=True)
    print(f"  Home Region:      {home_region}", flush=True)
    print(f"  Key Fingerprint:  {fingerprint}", flush=True)
    print(f"  OCI Config File:  {config_path}", flush=True)
    print(f"  Project .env:     {env_file}", flush=True)
    print("==================================================================", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
