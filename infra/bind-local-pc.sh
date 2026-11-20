#!/usr/bin/env bash
#
# infra/bind-local-pc.sh
#
# Binds your local PC to Oracle Cloud Infrastructure (OCI):
#   1. Generates 2048-bit RSA API Signing Key pair in ~/.oci/
#   2. Computes the OCI API key MD5 fingerprint
#   3. Creates ~/.oci/config with [DEFAULT] and [soc-project] profiles
#   4. Generates Ed25519 SSH key pair in ~/.ssh/soc-automation-ed25519
#   5. Supports --configure (update OCIDs in ~/.oci/config) and --verify (test OCI API auth)
#
# Usage:
#   bash infra/bind-local-pc.sh
#   bash infra/bind-local-pc.sh --configure --tenancy-ocid <ocid> --user-ocid <ocid> --region <region>
#   bash infra/bind-local-pc.sh --verify

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/.venv/bin:${HOME}/.local/bin:${PATH}"

OCI_DIR="${HOME}/.oci"
API_PRIV_KEY="${OCI_DIR}/oci_api_key.pem"
API_PUB_KEY="${OCI_DIR}/oci_api_key_public.pem"
OCI_CONFIG="${OCI_DIR}/config"

SSH_DIR="${HOME}/.ssh"
SSH_PRIV_KEY="${SSH_DIR}/soc-automation-ed25519"
SSH_PUB_KEY="${SSH_DIR}/soc-automation-ed25519.pub"

OCI_CLI_PROFILE="${OCI_CLI_PROFILE:-soc-project}"
DEFAULT_REGION="${OCI_REGION:-ap-mumbai-1}"

MODE="setup"
TENANCY_OCID="${EXPECTED_OCI_TENANCY_OCID:-YOUR_TENANCY_OCID}"
USER_OCID="${OCI_USER_OCID:-YOUR_USER_OCID}"
REGION="$DEFAULT_REGION"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verify)
            MODE="verify"
            shift
            ;;
        --configure)
            MODE="configure"
            shift
            ;;
        --tenancy-ocid)
            TENANCY_OCID="$2"
            shift 2
            ;;
        --user-ocid)
            USER_OCID="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

ensure_keys() {
    mkdir -p "$OCI_DIR"
    chmod 700 "$OCI_DIR"

    if [[ ! -f "$API_PRIV_KEY" ]]; then
        echo "=== Generating 2048-bit RSA OCI API Signing Key Pair ==="
        openssl genrsa -out "$API_PRIV_KEY" 2048 2>/dev/null
        chmod 600 "$API_PRIV_KEY"
        openssl rsa -pubout -in "$API_PRIV_KEY" -out "$API_PUB_KEY" 2>/dev/null
        chmod 644 "$API_PUB_KEY"
        echo "CREATED  Private key: $API_PRIV_KEY"
        echo "CREATED  Public key:  $API_PUB_KEY"
    else
        chmod 600 "$API_PRIV_KEY"
        if [[ ! -f "$API_PUB_KEY" ]]; then
            openssl rsa -pubout -in "$API_PRIV_KEY" -out "$API_PUB_KEY" 2>/dev/null
            chmod 644 "$API_PUB_KEY"
        fi
        echo "EXISTS   OCI API key pair in $OCI_DIR"
    fi

    FINGERPRINT=$(openssl rsa -pubout -outform DER -in "$API_PRIV_KEY" 2>/dev/null | openssl md5 -c | awk '{print $2}')

    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"

    if [[ ! -f "$SSH_PRIV_KEY" ]]; then
        echo "=== Generating Ed25519 SSH Key Pair for OCI Compute Instances ==="
        ssh-keygen -t ed25519 -f "$SSH_PRIV_KEY" -N "" -C "soc-automation-oci-key" >/dev/null
        chmod 600 "$SSH_PRIV_KEY"
        chmod 644 "$SSH_PUB_KEY"
        echo "CREATED  SSH key pair: $SSH_PRIV_KEY"
    else
        echo "EXISTS   SSH key pair: $SSH_PRIV_KEY"
    fi
}

write_oci_config() {
    local tenancy="$1"
    local user="$2"
    local region="$3"
    local fingerprint="$4"

    cat > "$OCI_CONFIG" <<EOF
[DEFAULT]
user=${user}
fingerprint=${fingerprint}
tenancy=${tenancy}
region=${region}
key_file=${API_PRIV_KEY}

[soc-project]
user=${user}
fingerprint=${fingerprint}
tenancy=${tenancy}
region=${region}
key_file=${API_PRIV_KEY}
EOF
    chmod 600 "$OCI_CONFIG"
    echo "UPDATED  OCI configuration file: $OCI_CONFIG"
}

ensure_keys

if [[ "$MODE" == "configure" ]]; then
    write_oci_config "$TENANCY_OCID" "$USER_OCID" "$REGION" "$FINGERPRINT"
    exit 0
fi

if [[ "$MODE" == "verify" ]]; then
    echo "=== Verifying Local PC -> Oracle Cloud (OCI) Connection ==="
    if ! command -v oci >/dev/null 2>&1; then
        echo "ERROR: 'oci' CLI is not on PATH. Activate your venv or add ~/.local/bin to PATH." >&2
        exit 1
    fi
    oci iam region-subscription list --profile "$OCI_CLI_PROFILE" --output table
    echo ""
    echo "SUCCESS: Your local PC is authenticated and bound to Oracle Cloud!"
    exit 0
fi

if [[ ! -f "$OCI_CONFIG" ]]; then
    write_oci_config "$TENANCY_OCID" "$USER_OCID" "$REGION" "$FINGERPRINT"
fi

echo ""
echo "=================================================================="
echo "  LOCAL PC ORACLE CLOUD (OCI) BINDING DETAILS"
echo "=================================================================="
echo "  OCI Config File:     $OCI_CONFIG"
echo "  API Private Key:     $API_PRIV_KEY (600 permissions)"
echo "  API Public Key:      $API_PUB_KEY"
echo "  API Key Fingerprint: $FINGERPRINT"
echo "  Compute SSH Key:     $SSH_PUB_KEY"
echo "------------------------------------------------------------------"
echo "  PUBLIC API KEY TO UPLOAD TO OCI CONSOLE (My Profile -> API keys):"
echo "------------------------------------------------------------------"
cat "$API_PUB_KEY"
echo "------------------------------------------------------------------"
echo "  Next Steps to Complete Binding:"
echo "  1. Copy the PUBLIC KEY block above."
echo "  2. In Oracle Cloud Console -> Top-right Profile -> My profile -> API keys -> Add API key."
echo "  3. Choose 'Paste a public key', paste it, and click Add."
echo "  4. Bind your Tenancy & User OCIDs into ~/.oci/config by running:"
echo "     bash infra/bind-local-pc.sh --configure --tenancy-ocid <tenancy_ocid> --user-ocid <user_ocid> --region <region>"
echo "  5. Test connectivity with:"
echo "     bash infra/bind-local-pc.sh --verify"
echo "=================================================================="
