#!/bin/sh
# Configures Postfix for the PROXY protocol measurements and runs it.
#
# The stock master.cf is kept and only added to. Writing one by hand leaves out
# the helper services smtpd needs and the server then warns on every session
# instead of serving it.
set -eu

readonly HOSTNAME_FQDN='mail.lab.test'
# The lab bridge. Only a client on it may send mail, so an accidental relay is
# not something this container can be used for.
readonly LAB='172.28.0.0/24'

postconf -e "myhostname = ${HOSTNAME_FQDN}"
postconf -e "mydestination = ${HOSTNAME_FQDN}, localhost"
postconf -e "mynetworks = 127.0.0.0/8 ${LAB}"
postconf -e 'inet_interfaces = all'
postconf -e 'inet_protocols = ipv4'
# The connect line names the client of every session, which is what the tests
# read the address out of.
postconf -e 'maillog_file = /dev/stdout'
postconf -e 'smtpd_client_restrictions = permit_mynetworks, reject'
postconf -e 'smtpd_recipient_restrictions = permit_mynetworks, reject'
# Nothing is delivered anywhere. The tests measure the session, not the mail.
postconf -e 'default_transport = discard'
postconf -e 'relay_transport = discard'
# Long enough that a test is never cut off mid-session, short enough that a
# forgotten connection does not hold a process for the rest of the run.
postconf -e 'smtpd_timeout = 30s'

# Port 25 sits behind the load balancer and is told to expect the header.
postconf -P 'smtp/inet/smtpd_upstream_proxy_protocol=haproxy'
# Port 26 is the same server without that setting, which is what a backend
# nobody configured for the header looks like.
postconf -M '26/inet=26 inet n - y - - smtpd'

newaliases 2>/dev/null || true

exec postfix start-fg
