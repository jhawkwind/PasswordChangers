#!/bin/bash
# This is to update the password in /etc/nslcd.conf.

# Define error conditions
ERR_NO_PRIVILEGES=101;
ERR_NO_NSLCDCONF_FILE=102;
ERR_FAILED_CHANGE=103;
ERR_FAILED_VERIFY=104;

# read parameters from the given environment variables.
BINDDN=${USERNAME}
OLD_BINDPW=${PASSWORD}
NEW_BINDPW=${NEWPASSWORD}
SUDOER=${SUDOER}
SUDOPW=${SUDOPASS}

ME="$(whoami)";

if [ "${ME}" != "root" ] && [ "${ME}" != "${SUDOER}" ] && [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: You must run as root or the ${SUDOER} user!"
	exit ${ERR_NO_PRIVILEGES};
fi

if ! [ -f /etc/nslcd.conf ]; then
	echo "ERROR: Cannot find /etc/nslcd.conf.";
	exit ${ERR_NO_NSLCDCONF_FILE};
fi

prechange_result=$(echo "${SUDOPW}" | sudo -p '' -S -s -- grep -c -P "^bindpw ${NEWPASSWORD}$" /etc/nslcd.conf;);
if [[ "${prechange_result}" -eq 1 ]]; then
	# If it matches new password already, exit with success. Don't change.
	echo "SUCCESS, not changed. Password is already set.";
	exit 0;
fi

echo "${SUDOPW}" | sudo -p '' -S -s -- sed -i -r "s|bindpw ${PASSWORD}|bindpw ${NEWPASSWORD}|" /etc/nslcd.conf;
if [[ "$?" -ne 0 ]]; then
	echo "${target_statement}";
	echo "FAILURE: Unable to replace old password.";
	exit ${ERR_FAILED_CHANGE};
fi

postchange_result$(echo "${SUDOPW}" | sudo -p '' -S -s -- grep -c -p "^bindpw ${NEWPASSWORD}$" /etc/nslcd.conf;);
if [[ "${postchange_result}" -ne 1 ]]; then
	echo "FAILURE: Cannot confirm password was changed.";
	exit ${ERR_FAILED_VERIFY};
fi

# Enforce permissions
if [[ "$(stat -c %a /etc/nslcd.conf)" != "600" ]]; then
	echo "${SUDOPW}" | sudo -p '' -S -s --chmod 600 /etc/nslcd.conf;
fi

# Enforce ownership
if [[ "$(stat -c %u /etc/nslcd.conf)" -ne 0 ]]; then
	echo "${SUDOPW}" | sudo -p '' -S -s -- chown 0 /etc/nslcd.conf;
fi

# Enforce group membership
if [[ "$(stat -c %g /etc/nslcd.conf)" -ne 0 ]]; then
	echo "${SUDOPW}" | sudo -p '' -S -s -- chown :0 /etc/nslcd.conf;
fi

# Enforce context if SELINUX is enabled.
if [[ "$(/sbin/getenforce)" =~ (E|e)nforcing ]]; then
	desired_context="^system_u:object_r:etc_t:.*";
	if ! [[ "$(stat -c %C /etc/nslcd.conf)" =~ ${desired_context} ]]; then
		echo "${SUDOPW}" | sudo -p '' -S -s -- chcon -u system_u -r object_r -t etc_t /etc/nslcd.conf;
	fi
fi

echo "SUCCESS!";
exit 0;