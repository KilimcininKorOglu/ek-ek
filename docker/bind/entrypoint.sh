#!/bin/sh
# Bring up the lab's name server with a fresh shared key.
#
# The key is generated here on every start and never written into the
# repository. A shared key in a tracked file is a credential published from the
# first commit, and one that is regenerated cannot be reused from a checkout.
#
# The zone is authoritative for the lab and everything else is forwarded to
# Docker's own resolver, so a node pointed here still finds the other
# containers by name.
set -eu

ZONE="${LAB_ZONE:?the zone to serve}"
KEY="${LAB_TSIG_KEY:?the name of the shared key}"
NODE1="${LAB_NODE1:?the address node1 answers on}"
SELF="${LAB_SELF:?the address this server answers on}"
SHARED=/shared

tsig-keygen -a hmac-sha256 "$KEY" > /etc/bind/tsig.key

# The bare value, for whoever configures the client side. The block above is
# what a name server reads; this is what an operator pastes.
mkdir -p "$SHARED"
sed -n 's/.*secret "\(.*\)";/\1/p' /etc/bind/tsig.key > "$SHARED/tsig.secret"
chmod 0644 "$SHARED/tsig.secret"

cat > /etc/bind/named.conf <<CONF
options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { none; };
    allow-query { any; };
    recursion yes;
    allow-recursion { any; };
    // Docker's embedded resolver, which is what answers container names.
    forwarders { 127.0.0.11; };
    forward only;
    // The lab zone is unsigned and the forwarder is not a validating
    // resolver, so validation here would refuse every answer.
    dnssec-validation no;
};

include "/etc/bind/tsig.key";

zone "$ZONE" {
    type primary;
    file "/var/lib/bind/db.$ZONE";
    // The only way anything is written: an update signed with the shared key.
    // Without this line the zone is read only and the whole point is gone.
    allow-update { key "$KEY"; };
};
CONF

mkdir -p /var/lib/bind
cat > "/var/lib/bind/db.$ZONE" <<ZONEFILE
\$TTL 60
@       IN SOA  ns.$ZONE. hostmaster.$ZONE. ( 1 3600 600 86400 60 )
@       IN NS   ns.$ZONE.
ns      IN A    $SELF
node1   IN A    $NODE1
ZONEFILE
chown -R bind:bind /var/lib/bind

named-checkconf /etc/bind/named.conf

# As the bind user, not as root. named drops every capability except the one
# it needs to bind port 53, so a root process without CAP_DAC_OVERRIDE is
# checked against ordinary permissions and cannot write the zone's journal.
# Without the journal every dynamic update is refused.
exec named -g -u bind -c /etc/bind/named.conf
