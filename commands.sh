#!/usr/bin/env bash
# =============================================================================
# LDAP Lab: OpenLDAP on Ubuntu Server LTS
# Command reference for the 10-phase implementation plan.
#
# ISOLATED LAB USE ONLY. Follow section by section; do NOT run blindly.
# Some steps are interactive (dpkg-reconfigure, password prompts).
# Edit the variables below first.
# =============================================================================

# ---- Variables (edit these) -------------------------------------------------
export LAB_IP="192.168.56.10"              # server IP on the isolated lab network
export LAB_HOST="ldap.lab.local"           # must match the certificate name
export BASE_DN="dc=example,dc=com"
export ADMIN_DN="cn=admin,${BASE_DN}"
export WORKDIR="$HOME/ldap-lab"
mkdir -p "$WORKDIR" && cd "$WORKDIR"


# =============================================================================
# PHASE 1: Environment preparation
# Provision an isolated VM (host-only/NAT). Then confirm connectivity.
# =============================================================================
ip addr show
ping -c 3 "$LAB_IP"            # run from the client VM
# Confirm the VM has NO route to production or the internet after setup.


# =============================================================================
# PHASE 2: Install OpenLDAP
# =============================================================================
sudo apt update
sudo apt install -y slapd ldap-utils

# Set the admin password and base DN (choose dc=example,dc=com, org "Example")
sudo dpkg-reconfigure slapd

# Validate
systemctl status slapd --no-pager
ldapsearch -x -H ldap://localhost -b "$BASE_DN" -s base


# =============================================================================
# PHASE 3: Directory structure design
# Base DN: dc=example,dc=com
#   ou=People  -> uid=alice, uid=bob
#   ou=Groups  -> cn=students, cn=administrators
# (Document this in your design notes; no commands needed.)
# =============================================================================


# =============================================================================
# PHASE 4: Schema configuration
# Debian/Ubuntu slapd loads core, cosine, nis and inetorgperson by default.
# =============================================================================
sudo ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config dn 2>/dev/null | grep -E "^dn:"
sudo ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config "(objectClass=olcDatabaseConfig)" dn 2>/dev/null | grep -E "^dn:"
# Note the database DN (usually olcDatabase={1}mdb,cn=config); it is used below.


# =============================================================================
# PHASE 5: Users and groups from LDIF
# =============================================================================

# Password hashes (salted SSHA). Paste the output into the LDIF below.
slappasswd -h '{SSHA}'

cat > base.ldif <<'EOF'
dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People

dn: ou=Groups,dc=example,dc=com
objectClass: organizationalUnit
ou: Groups
EOF

cat > users.ldif <<'EOF'
dn: uid=alice,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
uid: alice
cn: Alice Example
sn: Example
mail: alice@example.com
uidNumber: 10001
gidNumber: 5000
homeDirectory: /home/alice
userPassword: {SSHA}REPLACE_WITH_HASH

dn: uid=bob,ou=People,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
uid: bob
cn: Bob Example
sn: Example
mail: bob@example.com
uidNumber: 10002
gidNumber: 5000
homeDirectory: /home/bob
userPassword: {SSHA}REPLACE_WITH_HASH
EOF

cat > groups.ldif <<'EOF'
dn: cn=students,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: students
member: uid=bob,ou=People,dc=example,dc=com

dn: cn=administrators,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: administrators
member: uid=alice,ou=People,dc=example,dc=com
EOF

ldapadd -x -D "$ADMIN_DN" -W -f base.ldif
ldapadd -x -D "$ADMIN_DN" -W -f users.ldif
ldapadd -x -D "$ADMIN_DN" -W -f groups.ldif

# Validate
ldapsearch -x -D "$ADMIN_DN" -W -b "$BASE_DN" "(objectClass=*)" dn
ldapsearch -x -D "$ADMIN_DN" -W -b "ou=Groups,$BASE_DN" "(cn=students)" member


# =============================================================================
# PHASE 6: Authentication
# =============================================================================
# Correct password: should succeed and print the bind DN
ldapwhoami -x -D "uid=alice,ou=People,${BASE_DN}" -W
# Wrong password: should fail with "Invalid credentials (49)"
ldapwhoami -x -D "uid=alice,ou=People,${BASE_DN}" -w wrongpassword

# Change a user's password (prompts for old and new)
ldappasswd -x -D "uid=alice,ou=People,${BASE_DN}" -W -S "uid=alice,ou=People,${BASE_DN}"


# =============================================================================
# PHASE 7: Access control (least privilege) + disable anonymous access
# =============================================================================
# Adjust {1}mdb if Phase 4 showed a different database DN.
cat > acl.ldif <<'EOF'
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to dn.base="" by * read
olcAccess: {2}to * by self read by users read by * none
-
add: olcRequires
olcRequires: authc
EOF
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f acl.ldif

# Refuse anonymous binds globally
cat > noanon.ldif <<'EOF'
dn: cn=config
changetype: modify
add: olcDisallows
olcDisallows: bind_anon
EOF
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f noanon.ldif

# Verify the ACL
sudo ldapsearch -Y EXTERNAL -H ldapi:/// -b "olcDatabase={1}mdb,cn=config" olcAccess olcRequires 2>/dev/null

# Negative tests (expected: denied)
# Anonymous search (T07): should fail
ldapsearch -x -H ldap://localhost -b "ou=People,${BASE_DN}"
# Low-privilege write to another user's entry (T06): should fail
cat > bad-write.ldif <<'EOF'
dn: uid=alice,ou=People,dc=example,dc=com
changetype: modify
replace: mail
mail: changed@example.com
EOF
ldapmodify -x -D "uid=bob,ou=People,${BASE_DN}" -W -f bad-write.ldif   # expect "Insufficient access (50)"

# Positive test (T05): a user modifies an allowed attribute on their OWN entry
# (allowed only if you grant it; the ACL above lets users write their own userPassword).


# =============================================================================
# PHASE 8: TLS / security configuration
# =============================================================================

# 8.1 Lab CA and server certificate (with SAN matching $LAB_HOST)
openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt \
  -days 365 -subj "/CN=Lab CA"

openssl req -newkey rsa:2048 -nodes -keyout ldap.key -out ldap.csr \
  -subj "/CN=${LAB_HOST}"

cat > san.cnf <<EOF
subjectAltName = DNS:${LAB_HOST}
EOF

openssl x509 -req -in ldap.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out ldap.crt -days 365 -extfile san.cnf

# 8.2 Install the files with strict permissions
sudo mkdir -p /etc/ldap/tls
sudo cp ca.crt ldap.crt ldap.key /etc/ldap/tls/
sudo chown -R openldap:openldap /etc/ldap/tls
sudo chmod 600 /etc/ldap/tls/ldap.key

# 8.3 Name resolution for the lab host (server and client)
echo "${LAB_IP} ${LAB_HOST}" | sudo tee -a /etc/hosts

# 8.4 Point slapd at the certificates and require TLS
cat > tls.ldif <<'EOF'
dn: cn=config
changetype: modify
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/tls/ca.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/tls/ldap.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/tls/ldap.key
EOF
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f tls.ldif

# Require TLS (at least "tls=1") before binds/operations on the database
cat > require-tls.ldif <<'EOF'
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcSecurity
olcSecurity: tls=1
EOF
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f require-tls.ldif

# 8.5 Listen on the lab interface only
#   Edit /etc/default/slapd and set:
#   SLAPD_SERVICES="ldap://${LAB_IP}:389/ ldaps://${LAB_IP}:636/ ldapi:///"
sudo nano /etc/default/slapd
sudo systemctl restart slapd
sudo ss -tlnp | grep slapd

# 8.6 Client trusts the lab CA (copy ca.crt to the client first)
#   Add to /etc/ldap/ldap.conf on the client:
#     TLS_CACERT /etc/ldap/tls/ca.crt
#     URI ldap://ldap.lab.local
#     BASE dc=example,dc=com

# 8.7 Validate
# StartTLS search (T08): should succeed
ldapsearch -x -ZZ -H "ldap://${LAB_HOST}" -D "uid=alice,ou=People,${BASE_DN}" -W \
  -b "$BASE_DN" "(uid=bob)" uid mail
# Plaintext bind (should be rejected: "confidentiality required (13)")
ldapwhoami -x -H "ldap://${LAB_HOST}" -D "uid=alice,ou=People,${BASE_DN}" -W
# LDAPS (implicit TLS)
ldapwhoami -x -H "ldaps://${LAB_HOST}" -D "uid=alice,ou=People,${BASE_DN}" -W


# =============================================================================
# PHASE 9: Testing (T01-T11); record results in the Chapter 15 table
# =============================================================================

# T01 Server availability
systemctl is-active slapd
ldapsearch -x -ZZ -H "ldap://${LAB_HOST}" -D "$ADMIN_DN" -W -b "$BASE_DN" -s base dn

# T02 Valid authentication
ldapwhoami -x -ZZ -H "ldap://${LAB_HOST}" -D "uid=alice,ou=People,${BASE_DN}" -W

# T03 Invalid authentication (expect error 49)
ldapwhoami -x -ZZ -H "ldap://${LAB_HOST}" -D "uid=alice,ou=People,${BASE_DN}" -w wrongpassword

# T04 Directory search with a filter: members of a group
ldapsearch -x -ZZ -H "ldap://${LAB_HOST}" -D "uid=alice,ou=People,${BASE_DN}" -W \
  -b "ou=Groups,${BASE_DN}" "(cn=students)" member

# T05 Authorized access: user changes own password
ldappasswd -x -ZZ -H "ldap://${LAB_HOST}" -D "uid=bob,ou=People,${BASE_DN}" -W -S \
  "uid=bob,ou=People,${BASE_DN}"

# T06 Unauthorized write (expect Insufficient access, 50)
ldapmodify -x -ZZ -H "ldap://${LAB_HOST}" -D "uid=bob,ou=People,${BASE_DN}" -W -f bad-write.ldif

# T07 Anonymous search (expect failure)
ldapsearch -x -ZZ -H "ldap://${LAB_HOST}" -b "ou=People,${BASE_DN}"

# T08 TLS: verbose output should show a successful TLS negotiation
ldapsearch -x -ZZ -d1 -H "ldap://${LAB_HOST}" -D "$ADMIN_DN" -W -b "$BASE_DN" -s base 2>&1 | grep -i tls

# T09 Certificate validation: without trusting the lab CA, expect failure
LDAPTLS_CACERT=/etc/ssl/certs/ca-certificates.crt LDAPTLS_REQCERT=demand \
  ldapsearch -x -ZZ -H "ldap://${LAB_HOST}" -D "$ADMIN_DN" -W -b "$BASE_DN" -s base

# T10 Logging: enable stats logging, then review
cat > log.ldif <<'EOF'
dn: cn=config
changetype: modify
replace: olcLogLevel
olcLogLevel: stats
EOF
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f log.ldif
sudo journalctl -u slapd --no-pager -n 50
sudo journalctl -u slapd --no-pager | grep -E "BIND|SRCH|err=49"   # binds, searches, failed binds

# T11 Backup / recovery
sudo slapcat -n 1 -l "$WORKDIR/backup.ldif"
sudo chmod 600 "$WORKDIR/backup.ldif"      # backups contain hashes and PII
# Restore test (ONLY on a lab copy: slapadd needs the service stopped and an empty database)
#   sudo systemctl stop slapd
#   sudo -u openldap slapadd -n 1 -l "$WORKDIR/backup.ldif"
#   sudo systemctl start slapd

# Availability check: restart and reconnect
sudo systemctl restart slapd
ldapwhoami -x -ZZ -H "ldap://${LAB_HOST}" -D "uid=alice,ou=People,${BASE_DN}" -W


# =============================================================================
# PHASE 10: Documentation
# Archive the configuration for the final report
# =============================================================================
sudo slapcat -n 0 -l "$WORKDIR/config-export.ldif"   # cn=config export
tar czf ldap-lab-archive.tar.gz *.ldif san.cnf
