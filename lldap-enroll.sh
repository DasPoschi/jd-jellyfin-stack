#!/usr/bin/env bash
# =============================================================================
# LLDAP Domain Enrollment Script
# =============================================================================
# Enrolls Linux and macOS systems into an LLDAP directory domain.
#
# Supported systems:
#   Linux:  Debian/Ubuntu, RHEL/Fedora/CentOS/AlmaLinux/Rocky,
#           Arch/Manjaro, openSUSE/SLES
#   macOS:  12+ (Monterey and later)
#
# Usage:
#   sudo ./lldap-enroll.sh [options]
#
# Options:
#   -s, --server      LLDAP server URI       (e.g. ldap://lldap.example.com)
#   -b, --base-dn     Base DN                (e.g. dc=example,dc=com)
#   -D, --bind-dn     Bind DN for enrollment (e.g. uid=admin,ou=people,dc=example,dc=com)
#   -w, --bind-pw     Bind password          (prompted if omitted)
#   -p, --port        LDAP port              (default: 3890)
#       --tls         Enforce StartTLS / LDAPS
#       --dry-run     Show what would be done without applying changes
#       --uninstall   Remove LLDAP enrollment from this system
#   -h, --help        Show this help
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
LLDAP_SERVER=""
LLDAP_PORT="3890"
BASE_DN=""
BIND_DN=""
BIND_PW=""
USE_TLS="no"
DRY_RUN="no"
UNINSTALL="no"
SCRIPT_NAME="$(basename "$0")"
LOG_FILE="/var/log/lldap-enroll.log"

# ---------------------------------------------------------------------------
# Colors & helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
NC='\033[0m'

log()   { echo -e "${BLUE}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE" >&2; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "$LOG_FILE"; }

die() { err "$@"; exit 1; }

run_or_dry() {
    if [[ "$DRY_RUN" == "yes" ]]; then
        log "[DRY-RUN] $*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    sed -n '/^# Usage:/,/^# ====/{ /^# ====/d; s/^# \?//; p }' "$0"
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--server)   LLDAP_SERVER="$2"; shift 2 ;;
            -b|--base-dn)  BASE_DN="$2";      shift 2 ;;
            -D|--bind-dn)  BIND_DN="$2";      shift 2 ;;
            -w|--bind-pw)  BIND_PW="$2";      shift 2 ;;
            -p|--port)     LLDAP_PORT="$2";   shift 2 ;;
            --tls)         USE_TLS="yes";     shift   ;;
            --dry-run)     DRY_RUN="yes";     shift   ;;
            --uninstall)   UNINSTALL="yes";   shift   ;;
            -h|--help)     usage ;;
            *) die "Unknown option: $1" ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
require_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root (use sudo)."
}

prompt_missing() {
    if [[ -z "$LLDAP_SERVER" ]]; then
        read -rp "LLDAP server URI (e.g. ldap://lldap.example.com): " LLDAP_SERVER
    fi
    if [[ -z "$BASE_DN" ]]; then
        read -rp "Base DN (e.g. dc=example,dc=com): " BASE_DN
    fi
    if [[ -z "$BIND_DN" ]]; then
        BIND_DN="uid=admin,ou=people,${BASE_DN}"
        log "Using default Bind DN: $BIND_DN"
    fi
    if [[ -z "$BIND_PW" ]]; then
        read -rsp "Bind password: " BIND_PW
        echo
    fi

    # Normalise server URI
    if [[ "$LLDAP_SERVER" != ldap://* && "$LLDAP_SERVER" != ldaps://* ]]; then
        if [[ "$USE_TLS" == "yes" ]]; then
            LLDAP_SERVER="ldaps://${LLDAP_SERVER}"
        else
            LLDAP_SERVER="ldap://${LLDAP_SERVER}"
        fi
    fi

    # Append port if not already in URI
    if ! echo "$LLDAP_SERVER" | grep -qE ':[0-9]+$'; then
        LLDAP_SERVER="${LLDAP_SERVER}:${LLDAP_PORT}"
    fi
}

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------
detect_os() {
    OS_TYPE=""       # linux | macos
    DISTRO_FAMILY="" # debian | rhel | arch | suse
    DISTRO_ID=""     # ubuntu, fedora, arch, opensuse-leap, ...
    DISTRO_VER=""

    case "$(uname -s)" in
        Linux)
            OS_TYPE="linux"
            if [[ -f /etc/os-release ]]; then
                # shellcheck source=/dev/null
                . /etc/os-release
                DISTRO_ID="${ID:-unknown}"
                DISTRO_VER="${VERSION_ID:-}"
                case "$DISTRO_ID" in
                    ubuntu|debian|raspbian|linuxmint|pop)
                        DISTRO_FAMILY="debian" ;;
                    fedora|centos|rhel|rocky|almalinux|ol|amzn)
                        DISTRO_FAMILY="rhel" ;;
                    arch|manjaro|endeavouros|garuda)
                        DISTRO_FAMILY="arch" ;;
                    opensuse*|sles|suse)
                        DISTRO_FAMILY="suse" ;;
                    *)
                        # Fallback: check ID_LIKE
                        case "${ID_LIKE:-}" in
                            *debian*|*ubuntu*)  DISTRO_FAMILY="debian" ;;
                            *rhel*|*fedora*)    DISTRO_FAMILY="rhel"   ;;
                            *arch*)             DISTRO_FAMILY="arch"   ;;
                            *suse*)             DISTRO_FAMILY="suse"   ;;
                            *) die "Unsupported Linux distribution: $DISTRO_ID" ;;
                        esac
                        ;;
                esac
            else
                die "Cannot detect Linux distribution (missing /etc/os-release)."
            fi
            ;;
        Darwin)
            OS_TYPE="macos"
            DISTRO_ID="macos"
            DISTRO_VER="$(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
            ;;
        *)
            die "Unsupported operating system: $(uname -s)"
            ;;
    esac

    log "Detected: OS=$OS_TYPE  Distro=$DISTRO_ID ($DISTRO_FAMILY)  Version=$DISTRO_VER"
}

# =============================================================================
# LINUX ENROLLMENT
# =============================================================================

# ---------------------------------------------------------------------------
# Package installation
# ---------------------------------------------------------------------------
install_packages_debian() {
    log "Installing LDAP client packages (apt) ..."
    export DEBIAN_FRONTEND=noninteractive
    run_or_dry apt-get update -qq
    run_or_dry apt-get install -y -qq \
        libnss-ldapd libpam-ldapd nslcd nscd ldap-utils \
        libpam-mkhomedir
}

install_packages_rhel() {
    log "Installing LDAP client packages (dnf/yum) ..."
    local pkg_mgr="dnf"
    command -v dnf &>/dev/null || pkg_mgr="yum"
    run_or_dry $pkg_mgr install -y \
        nss-pam-ldapd nscd openldap-clients oddjob-mkhomedir
}

install_packages_arch() {
    log "Installing LDAP client packages (pacman) ..."
    run_or_dry pacman -Sy --noconfirm \
        nss-pam-ldapd nscd openldap pam
}

install_packages_suse() {
    log "Installing LDAP client packages (zypper) ..."
    run_or_dry zypper --non-interactive install \
        nss-pam-ldapd nscd openldap2-client pam_ldap
}

install_linux_packages() {
    case "$DISTRO_FAMILY" in
        debian) install_packages_debian ;;
        rhel)   install_packages_rhel   ;;
        arch)   install_packages_arch   ;;
        suse)   install_packages_suse   ;;
    esac
    ok "Packages installed."
}

# ---------------------------------------------------------------------------
# nslcd configuration (common across Linux distros)
# ---------------------------------------------------------------------------
configure_nslcd() {
    log "Configuring nslcd ..."

    local tls_config=""
    if [[ "$USE_TLS" == "yes" ]]; then
        tls_config="ssl start_tls
tls_reqcert allow"
    fi

    local nslcd_conf="/etc/nslcd.conf"
    run_or_dry tee "$nslcd_conf" > /dev/null <<NSLCD_EOF
# LLDAP nslcd configuration - generated by $SCRIPT_NAME
uid nslcd
gid nslcd

uri ${LLDAP_SERVER}

base   ${BASE_DN}
base   group  ou=groups,${BASE_DN}
base   passwd ou=people,${BASE_DN}
base   shadow ou=people,${BASE_DN}

binddn ${BIND_DN}
bindpw ${BIND_PW}

# LLDAP attribute mappings
filter passwd (objectClass=person)
map    passwd uid           uid
map    passwd uidNumber     uidNumber
map    passwd gidNumber     gidNumber
map    passwd homeDirectory homeDirectory
map    passwd loginShell    loginShell
map    passwd gecos         displayName

filter group (objectClass=groupOfUniqueNames)
map    group  cn            cn
map    group  gidNumber     gidNumber
map    group  member        uniqueMember

${tls_config}
NSLCD_EOF

    run_or_dry chmod 600 "$nslcd_conf"
    ok "nslcd.conf written."
}

# ---------------------------------------------------------------------------
# NSS configuration
# ---------------------------------------------------------------------------
configure_nss() {
    log "Configuring NSS (nsswitch.conf) ..."

    local nsswitch="/etc/nsswitch.conf"
    if [[ -f "$nsswitch" ]]; then
        run_or_dry cp "$nsswitch" "${nsswitch}.bak.$(date +%s)"
    fi

    # Ensure ldap is listed in passwd, group, shadow lines
    for db in passwd group shadow; do
        if grep -q "^${db}:" "$nsswitch" 2>/dev/null; then
            if ! grep -q "ldap" <(grep "^${db}:" "$nsswitch"); then
                run_or_dry sed -i "s/^\(${db}:.*\)/\1 ldap/" "$nsswitch"
            fi
        else
            echo "${db}: files ldap" | run_or_dry tee -a "$nsswitch" > /dev/null
        fi
    done
    ok "nsswitch.conf updated."
}

# ---------------------------------------------------------------------------
# PAM configuration
# ---------------------------------------------------------------------------
configure_pam() {
    log "Configuring PAM for automatic home directory creation ..."

    case "$DISTRO_FAMILY" in
        debian)
            run_or_dry pam-auth-update --enable mkhomedir 2>/dev/null || true
            ;;
        rhel)
            run_or_dry authselect select sssd with-mkhomedir --force 2>/dev/null || {
                # Fallback for older systems without authselect
                local pam_session="/etc/pam.d/system-auth"
                if [[ -f "$pam_session" ]] && ! grep -q pam_mkhomedir "$pam_session"; then
                    echo "session optional pam_mkhomedir.so skel=/etc/skel umask=077" \
                        | run_or_dry tee -a "$pam_session" > /dev/null
                fi
            }
            # Enable oddjobd for mkhomedir
            run_or_dry systemctl enable --now oddjobd 2>/dev/null || true
            ;;
        arch|suse)
            local pam_session="/etc/pam.d/system-login"
            [[ "$DISTRO_FAMILY" == "suse" ]] && pam_session="/etc/pam.d/common-session"
            if [[ -f "$pam_session" ]] && ! grep -q pam_mkhomedir "$pam_session"; then
                echo "session optional pam_mkhomedir.so skel=/etc/skel umask=077" \
                    | run_or_dry tee -a "$pam_session" > /dev/null
            fi
            ;;
    esac
    ok "PAM configured."
}

# ---------------------------------------------------------------------------
# Enable & start services
# ---------------------------------------------------------------------------
enable_services_linux() {
    log "Enabling and starting services ..."
    for svc in nslcd nscd; do
        if systemctl list-unit-files "${svc}.service" &>/dev/null; then
            run_or_dry systemctl enable --now "$svc"
            ok "$svc enabled and started."
        fi
    done
}

# ---------------------------------------------------------------------------
# Connectivity test
# ---------------------------------------------------------------------------
test_ldap_connection() {
    log "Testing LDAP connectivity ..."
    if command -v ldapsearch &>/dev/null; then
        if ldapsearch -x -H "$LLDAP_SERVER" -D "$BIND_DN" -w "$BIND_PW" \
            -b "$BASE_DN" "(objectClass=person)" uid 2>/dev/null | grep -q "uid:"; then
            ok "LDAP connection successful - users found."
        else
            warn "LDAP connection established but no users found (this may be expected)."
        fi
    else
        warn "ldapsearch not available - skipping connection test."
    fi
}

# ---------------------------------------------------------------------------
# Main Linux enrollment
# ---------------------------------------------------------------------------
enroll_linux() {
    install_linux_packages
    configure_nslcd
    configure_nss
    configure_pam
    enable_services_linux
    test_ldap_connection

    echo ""
    ok "========================================"
    ok "  Linux LLDAP enrollment complete!"
    ok "========================================"
    log "LDAP users can now log in via SSH or console."
    log "Home directories will be created automatically on first login."
    log "Verify with:  getent passwd"
}

# =============================================================================
# macOS ENROLLMENT
# =============================================================================

configure_macos_ldap() {
    log "Configuring macOS LDAP directory binding ..."

    local server_host
    server_host="$(echo "$LLDAP_SERVER" | sed 's|ldaps\?://||; s|:[0-9]*$||')"

    local node_name="/LDAPv3/${server_host}"
    local search_base="$BASE_DN"

    # Remove existing LDAP config for this server if present
    run_or_dry dsconfigldap -r "$server_host" 2>/dev/null || true

    # Add LDAP server
    local tls_flag=""
    [[ "$USE_TLS" == "yes" ]] && tls_flag="-e"

    log "Adding LDAP server: $server_host (port $LLDAP_PORT) ..."
    run_or_dry dsconfigldap -a "$server_host" \
        -n "$server_host" \
        -p "$LLDAP_PORT" \
        ${tls_flag:+"$tls_flag"} 2>/dev/null || warn "dsconfigldap binding may need manual adjustment."

    # Configure search policy to include LDAP
    log "Adding LDAP to directory search path ..."
    local current_search
    current_search="$(dscl /Search -read / CSPSearchPath 2>/dev/null || true)"

    if ! echo "$current_search" | grep -q "$node_name"; then
        run_or_dry dscl /Search -append / CSPSearchPath "$node_name"
        run_or_dry dscl /Search/Contacts -append / CSPSearchPath "$node_name"
    fi

    # Configure attribute mappings for LLDAP via plist
    log "Configuring LDAP attribute mappings for LLDAP ..."
    local plist="/Library/Preferences/OpenDirectory/Configurations/LDAPv3/${server_host}.plist"

    if [[ -f "$plist" ]]; then
        # Set search bases
        run_or_dry /usr/libexec/PlistBuddy -c \
            "Set :template\ search\ base:1 ${search_base}" "$plist" 2>/dev/null || true

        # Configure user mapping search base
        run_or_dry defaults write "$plist" "module options" -dict-add \
            "AppleODClient" "<dict><key>searchBase</key><string>${search_base}</string></dict>" \
            2>/dev/null || true
    fi

    # Configure auto-mount home directories
    log "Configuring automatic home directory creation ..."
    local auto_home_plist="/etc/pam.d/authorization"

    # Use createmobileaccount or login hook for home dir creation
    run_or_dry defaults write /Library/Preferences/com.apple.loginwindow \
        EnableExternalAccounts -bool true 2>/dev/null || true

    # Create a LaunchDaemon for home directory creation on login
    local mkhomedir_plist="/Library/LaunchDaemons/com.lldap.mkhomedir.plist"
    if [[ "$DRY_RUN" != "yes" ]]; then
        cat > "$mkhomedir_plist" <<'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.lldap.mkhomedir</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>
            /usr/bin/dscl . -list /Users UniqueID | while read user uid; do
                if [ "$uid" -ge 1000 ] 2>/dev/null; then
                    homedir=$(/usr/bin/dscl . -read /Users/"$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
                    if [ -n "$homedir" ] &amp;&amp; [ ! -d "$homedir" ]; then
                        /bin/mkdir -p "$homedir"
                        /usr/sbin/chown "$user" "$homedir"
                        /bin/chmod 755 "$homedir"
                        /usr/bin/ditto /System/Library/User\ Template/English.lproj/ "$homedir/" 2>/dev/null || true
                    fi
                fi
            done
        </string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer>
</dict>
</plist>
PLIST_EOF
        chmod 644 "$mkhomedir_plist"
        chown root:wheel "$mkhomedir_plist"
        launchctl load -w "$mkhomedir_plist" 2>/dev/null || true
    else
        log "[DRY-RUN] Would create $mkhomedir_plist"
    fi

    ok "macOS LDAP directory binding configured."
}

test_macos_connection() {
    log "Testing macOS LDAP connection ..."
    local server_host
    server_host="$(echo "$LLDAP_SERVER" | sed 's|ldaps\?://||; s|:[0-9]*$||')"

    if dscl "/LDAPv3/${server_host}" -list /Users 2>/dev/null | head -5 | grep -q .; then
        ok "macOS LDAP connection successful - users found."
    else
        warn "Could not list LDAP users. Check configuration in System Preferences > Users & Groups > Login Options > Network Account Server."
    fi
}

enroll_macos() {
    configure_macos_ldap
    test_macos_connection

    echo ""
    ok "========================================"
    ok "  macOS LLDAP enrollment complete!"
    ok "========================================"
    log "LDAP users should now be visible via: dscl /LDAPv3/<server> -list /Users"
    log "You may also configure this in System Preferences > Users & Groups."
}

# =============================================================================
# UNINSTALL
# =============================================================================

uninstall_linux() {
    log "Removing LLDAP enrollment from Linux ..."

    # Stop services
    for svc in nslcd nscd; do
        systemctl disable --now "$svc" 2>/dev/null || true
    done

    # Restore nsswitch.conf backup
    local nsswitch="/etc/nsswitch.conf"
    local latest_backup
    latest_backup="$(ls -t ${nsswitch}.bak.* 2>/dev/null | head -1)"
    if [[ -n "$latest_backup" ]]; then
        run_or_dry cp "$latest_backup" "$nsswitch"
        ok "Restored nsswitch.conf from backup."
    else
        # Remove ldap from nsswitch entries
        run_or_dry sed -i 's/ ldap//g' "$nsswitch"
        ok "Removed ldap from nsswitch.conf."
    fi

    # Remove nslcd config
    [[ -f /etc/nslcd.conf ]] && run_or_dry rm -f /etc/nslcd.conf

    # Remove mkhomedir PAM entries
    case "$DISTRO_FAMILY" in
        debian) pam-auth-update --remove mkhomedir 2>/dev/null || true ;;
        rhel)   authselect select sssd --force 2>/dev/null || true ;;
    esac

    ok "LLDAP enrollment removed from Linux."
}

uninstall_macos() {
    log "Removing LLDAP enrollment from macOS ..."

    local server_host
    server_host="$(echo "$LLDAP_SERVER" | sed 's|ldaps\?://||; s|:[0-9]*$||')"

    # Remove LDAP server binding
    run_or_dry dsconfigldap -r "$server_host" 2>/dev/null || true

    # Remove from search path
    run_or_dry dscl /Search -delete / CSPSearchPath "/LDAPv3/${server_host}" 2>/dev/null || true
    run_or_dry dscl /Search/Contacts -delete / CSPSearchPath "/LDAPv3/${server_host}" 2>/dev/null || true

    # Remove LaunchDaemon
    local mkhomedir_plist="/Library/LaunchDaemons/com.lldap.mkhomedir.plist"
    if [[ -f "$mkhomedir_plist" ]]; then
        launchctl unload -w "$mkhomedir_plist" 2>/dev/null || true
        run_or_dry rm -f "$mkhomedir_plist"
    fi

    ok "LLDAP enrollment removed from macOS."
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_args "$@"
    require_root

    # Initialise log
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "--- LLDAP enrollment $(date -Iseconds) ---" >> "$LOG_FILE"

    detect_os
    prompt_missing

    log "Server:  $LLDAP_SERVER"
    log "Base DN: $BASE_DN"
    log "Bind DN: $BIND_DN"
    [[ "$DRY_RUN" == "yes" ]] && warn "DRY-RUN mode - no changes will be applied."

    if [[ "$UNINSTALL" == "yes" ]]; then
        case "$OS_TYPE" in
            linux) uninstall_linux ;;
            macos) uninstall_macos ;;
        esac
        ok "Uninstall complete."
        exit 0
    fi

    case "$OS_TYPE" in
        linux) enroll_linux ;;
        macos) enroll_macos ;;
    esac
}

main "$@"
