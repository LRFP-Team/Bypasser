#!/system/bin/sh
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EOF=255
readonly VK_POWER=13
readonly VK_SCREEN=20
readonly VK_UP=38
readonly VK_DOWN=40
readonly moduleName="Bypasser"
readonly moduleId="bypasser"
readonly actionFolderPath="$(dirname "$0")"
readonly webrootName="webroot"
readonly webrootFolderPath="${webrootName}"
readonly actionPropFileName="action.prop"
readonly actionPropFilePath="${webrootFolderPath}/${actionPropFileName}"
readonly defaultReadTimeout=5
readonly tmpDirectoryPath="/data/local/tmp"

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

function getTheKeyPressed
{
	local readTimeout namedPipeFilePath namedPipeFileName childProcessID pressString pressCode
	if echo "$1" | grep -qE '^[1-9][0-9]*$';
	then
		readTimeout=$1
	else
		readTimeout=${defaultReadTimeout}
	fi
	
	# read -r -t ${readTimeout} pressString < <(getevent -ql) #
	case "$2" in
		"${tmpDirectoryPath}/"*[!\/]*)
			namedPipeFilePath=$2
			;;
		*)
			namedPipeFileName="${moduleID}$(date +%Y%m%d%H%M%S%N).$$"
			namedPipeFilePath="${tmpDirectoryPath}/${namedPipeFileName}"
			;;
	esac
	mkfifo "${namedPipeFilePath}" 2>/dev/null || { echo "Failed to create the named pipe file \"${namedPipeFilePath}\". "; return ${EOF}; }
	getevent -ql > "${namedPipeFilePath}" &
	childProcessID=$!
	read -r -t ${readTimeout} pressString < "${namedPipeFilePath}"
	pressCode=$?
	kill ${childProcessID} 2>/dev/null
	wait ${childProcessID} 2>/dev/null
	rm -f "${namedPipeFilePath}"
	# pressCode=$? #
	
	if [[ ${EXIT_SUCCESS} == ${pressCode} ]];
	then
		if [[ "${pressString}" == *KEY_VOLUMEUP* ]];
		then
			echo "The [+] was pressed. "
			return ${VK_UP}
		elif [[ "${pressString}" == *KEY_VOLUMEDOWN* ]];
		then
			echo "The [-] was pressed. "
			return ${VK_DOWN}
		elif [[ "${pressString}" == *KEY_POWER* ]];
		then
			echo "The power key was pressed. "
			return ${VK_POWER}
		elif [[ "${pressString}" == *ABS_MT_TRACKING_ID* ]];
		then
			echo "The screen was pressed. "
			return ${VK_SCREEN}
		else
			echo "The following unknown event occurred. "
			echo "${pressString}" | sed 's/^/\t/'
			return ${EXIT_FAILURE}
		fi
	else
		echo "Users did not respond within ${readTimeout} second(s). "
		return ${EOF}
	fi
}

exitCode=${EXIT_SUCCESS}
clearCaches > /dev/null 2>&1
chmod 755 "${actionFolderPath}" 2>/dev/null && cd "${actionFolderPath}" 2>/dev/null
if [[ $? == ${EXIT_SUCCESS} && "$(basename "$(pwd)")" == "${moduleId}" ]];
then
	setPermissions > /dev/null 2>&1
	if [[ ! -f "${actionPropFilePath}" ]];
	then
		mkdir -p "${webrootFolderPath}" && echo "A" > "${actionPropFilePath}"
		if [[ $? -eq ${EXIT_SUCCESS} ]];
		then
			echo "The action configuration file \"${actionPropFilePath}\" was missing and recovered successfully. "
		else
			echo "The action configuration file \"${actionPropFilePath}\" was missing and could not be recovered. "
		fi
		setPermissions > /dev/null 2>&1
	fi
	if [[ -f "${actionPropFilePath}" ]];
	then
		target="$(cat "${actionPropFilePath}")";
		if [[ "A" == "${target}" || "B" == "${target}" ]];
		then
			actionPath="action${target}.sh"
			if [[ -f "${actionPath}" ]];
			then
				if [[ -x "${actionPath}" ]];
				then
					if sh -n "${actionPath}";
					then
						sh "${actionPath}" "$@"
						exitCode=$?
					else
						echo "Failed to execute \`\`action.sh\`\` since the necessary script \`\`${actionPath}\`\` failed to pass the local shell syntax check (sh). "
						echo "Please try to flash the latest version of the ${moduleName} rooting-layer system module. "
						exitCode=${EXIT_FAILURE}
					fi
				else
					echo "Failed to execute \`\`action.sh\`\` since the necessary script \`\`${actionPath}\`\` was not executable. "
					echo "Please try to flash the latest version of the ${moduleName} rooting-layer system module. "
					exitCode=${EXIT_FAILURE}
				fi
			else
				echo "Failed to execute \`\`action.sh\`\` since the necessary script \`\`${actionPath}\`\` was missing. "
				echo "Please try to flash the latest version of the ${moduleName} rooting-layer system module. "
				exitCode=${EXIT_FAILURE}
			fi
		else
			echo "Failed to execute \`\`action.sh\`\` since an improper action configuration file was detected. "
			echo "Please try to flash the latest version of the ${moduleName} rooting-layer system module. "
			exitCode=${EXIT_FAILURE}
		fi
	else
		echo "Failed to execute \`\`action.sh\`\` since the action configuration file \"${actionPropFilePath}\" was missing and unrecoverable. "
		echo "Please try to flash the latest version of the ${moduleName} rooting-layer system module. "
		exitCode=${EXIT_FAILURE}
	fi
	setPermissions > /dev/null 2>&1 && chmod 755 "${actionFolderPath}" 2>/dev/null
else
	echo "Failed to execute \`\`action.sh\`\` since the working directory \"$(pwd)\" is unexpected. "
	echo "Please try to flash the latest version of the ${moduleName} rooting-layer system module. "
	exitCode=${EOF}
fi
clearCaches > /dev/null 2>&1
pauseFlag="false"
if [[ "true" == "${KSU}" && "true" != "${KSU_SUKISU}" ]];
then
	pauseFlag="true"
fi
if [[ "true" == "${pauseFlag}" || "true" == "${APATCH}" ]];
then
	if [[ $# -lt 1 ]];
	then
		echo "Please press the [+] or [-] key to exit. "
		vk=0
		while [[ ${VK_UP} -ne ${vk} && ${VK_DOWN} -ne ${vk} ]]
		do
			content="$(getTheKeyPressed)"
			vk=$?
		done
	fi
fi
exit ${exitCode}
