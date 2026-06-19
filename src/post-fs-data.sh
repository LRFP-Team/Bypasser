#!/system/bin/sh
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EOF=255
readonly moduleName="Bypasser"
readonly moduleId="bypasser"
readonly moduleFolderPath="$(dirname "$0")"

function clearCaches
{
	sync && echo 3 > /proc/sys/vm/drop_caches
	return $?
}

function setPermissions
{
	returnCode=${EXIT_SUCCESS}
	if [[ -n "$(find . -type d -exec chmod 555 {} \; 2>&1)" ]];
	then
		returnCode=${EXIT_FAILURE}
	fi
	if [[ -n "$(find . -type f ! -name "*.sh" -exec chmod 444 {} \; 2>&1)" ]];
	then
		returnCode=${EXIT_FAILURE}
	fi
	if [[ -n "$(find . -type f -name "*.sh" -exec chmod 544 {} \; 2>&1)" ]];
	then
		returnCode=${EXIT_FAILURE}
	fi
	if ! chown -R root:root ".";
	then
		returnCode=${EXIT_FAILURE}
	fi
	return ${returnCode}
}

clearCaches > /dev/null 2>&1
chmod 755 "${moduleFolderPath}" 2>/dev/null && cd "${moduleFolderPath}" 2>/dev/null
if [[ $? -eq ${EXIT_SUCCESS} && "$(basename "$(pwd)")" == "${moduleId}" ]];
then
	setPermissions > /dev/null 2>&1
	# TODO #
	setPermissions > /dev/null 2>&1 && chmod 755 "${moduleFolderPath}" 2>/dev/null
else
	exit ${EXIT_FAILURE}
fi
clearCaches > /dev/null 2>&1
exit ${EXIT_SUCCESS}
