#/system/bin/sh
# Welcome #
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EOF=255
readonly VK_POWER=13
readonly VK_SCREEN=20
readonly VK_UP=38
readonly VK_DOWN=40
readonly moduleName="Bypasser"
readonly moduleId="bypasser"
readonly defaultTimeout=5
readonly outerSymbolCount=200
readonly innerSymbolCount=100
readonly startTime=$(date +%s%N)

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

ui_print ""
ui_print $(yes "#" | head -n ${outerSymbolCount} | tr -d '\n')
ui_print "Welcome to the installer of the ${moduleName} rooting-layer system module! "
ui_print "The absolute path to this script is \"$(cd "$(dirname "$0")" && pwd)/$(basename "$0")\". "
clearCaches
if [[ $? -eq ${EXIT_SUCCESS} ]];
then
	ui_print "Successfully cleared caches. "
else
	ui_print "Warning: Failed to clear caches. "
fi
chmod 755 "${MODPATH}" && cd "${MODPATH}"
if [[ $? -eq ${EXIT_SUCCESS} && "$(basename "$(pwd)")" == "${moduleId}" ]];
then
	ui_print "The current working directory is \"$(pwd)\". "
else
	abort "Error: The working directory \"$(pwd)\" is unexpected. "
fi
setPermissions
if [[ $? -eq ${EXIT_SUCCESS} ]];
then
	ui_print "Successfully set permissions. "
else
	ui_print "Warning: Failed to set permissions. "
fi

# Manager #
readonly MIN_APATCH_VER_CODE=10927
readonly MIN_KSU_VER_CODE=11981
readonly MIN_MAGISK_VER_CODE=28000

if $BOOTMODE;
then
	if [[ "${APATCH}" == "true" ]];
	then
		if [[ ${APATCH_VER_CODE} -ge ${MIN_APATCH_VER_CODE} ]];
		then
			ui_print "The action button is supported (Apatch ${APATCH_VER_CODE} >= ${MIN_APATCH_VER_CODE}). "
		else
			ui_print "Warning: The action button is not supported (Apatch ${APATCH_VER_CODE}). You can update dynamic configurations only by flashing this module. Please try to use the latest Apatch (>= ${MIN_APATCH_VER_CODE}). "
		fi
	elif [[ "${KSU}" == "true" ]];
	then
		if [[ ${KSU_VER_CODE} -ge ${MIN_KSU_VER_CODE} ]];
		then
			ui_print "The action button is supported (KSU ${KSU_VER_CODE} >= ${MIN_KSU_VER_CODE}). "
		else
			ui_print "Warning: The action button is not supported (KSU ${KSU_VER_CODE}). You can update dynamic configurations only by flashing this module. Please try to use the latest KSU (>= ${MIN_KSU_VER_CODE}). "
		fi
	elif [[ -n "${MAGISK_VER_CODE}" ]];
	then
		if [[ ${MAGISK_VER_CODE} -ge ${MIN_MAGISK_VER_CODE} ]];
		then
			ui_print "The action button is supported (Magisk ${MAGISK_VER_CODE} >= ${MIN_MAGISK_VER_CODE}). "
		else
			ui_print "Warning: The action button is not supported (Magisk ${MAGISK_VER_CODE}). You can update dynamic configurations only by flashing this module. Please try to use the latest Magisk (>= ${MIN_MAGISK_VER_CODE}). "
		fi
	else
		ui_print "Warning: Cannot guarantee whether the action button is supported. You may need to update dynamic configurations by flashing this module. "
	fi	
else
	ui_print "Warning: Installing from recovery does not make sense currently. You may need to update dynamic configurations by flashing this module. "
fi

# Hash #
sha512SuccessCount=0
sha512TotalCount=0

for filePath in $(find . -type f ! -name "*.sha512");
do
	sha512TotalCount=$(expr ${sha512TotalCount} + 1)
	if [[ ${sha512TotalCount} -ge 1 && ${sha512TotalCount} -le 9 ]];
	then
		sha512TotalCountString="0${sha512TotalCount}"
	else
		sha512TotalCountString="${sha512TotalCount}"
	fi
	sha512Computed=$(sha512sum "${filePath}" | cut -d " " -f1)
	sha512FilePath="${filePath}.sha512"
	if [[ -f "${sha512FilePath}" ]];
	then
		sha512Expected="$(cat "${sha512FilePath}")"
		if [[ "${sha512Computed}" == "${sha512Expected}" ]];
		then
			if [[ "${filePath}" =~ \.sh$ ]];
			then
				if sh -n "${filePath}";
				then
					sha512SuccessCount=$(expr ${sha512SuccessCount} + 1)
					ui_print "[${sha512TotalCountString}] Successfully verified \"${filePath}\" and it successfully passed the local shell syntax check (sh). "
				else
					ui_print "[${sha512TotalCountString}] Successfully verified \"${filePath}\" but it failed to pass the local shell syntax check (sh). "
				fi
			else
				sha512SuccessCount=$(expr ${sha512SuccessCount} + 1)
				ui_print "[${sha512TotalCountString}] Successfully verified \"${filePath}\". "
			fi
		else
			ui_print "[${sha512TotalCountString}] Failed to verify \"${filePath}\". "
		fi
	else
		ui_print "[${sha512TotalCountString}] Failed to find the corresponding SHA-512 value file to verify \"${filePath}\". "
	fi
done
ui_print "Finished checking ${sha512SuccessCount} / ${sha512TotalCount} file(s). "
if [[ ${sha512TotalCount} == ${sha512SuccessCount} ]];
then
	ui_print "Successfully verified all the files and they all passed the local shell syntax check (sh). "
	find . -type f -name "*.sha512" -delete
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		ui_print "Successfully removed all the SHA-512 value files. "
	else
		ui_print "Warning: Failed to remove all the SHA-512 value files. "
	fi
else
	abort "Error: Failed to verify all the files or some of the scripts failed to pass the local shell syntax check (sh). "
fi

# Action #
readonly actionFilePath="action.sh"
gapTime=0

function getTheKeyPressed
{
	if echo "$1" | grep -qE '^[1-9][0-9]*$';
	then
		timeout=$1
	else
		timeout=${defaultTimeout}
	fi
	read -r -t ${timeout} pressString < <(getevent -ql)
	pressCode=$?
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
		echo "Users did not respond within ${timeout} second(s). "
		return ${EOF}
	fi
}

if [[ -f "${actionFilePath}" ]];
then
	if [[ -x "${actionFilePath}" ]];
	then
		if ! sh -n "${actionFilePath}";
		then
			abort "Error: The \`\`"${actionFilePath}"\`\` failed to pass the local shell syntax check (sh). "
		fi
	else
		abort "Error: The \`\`"${actionFilePath}"\`\` was not executable. "
	fi
else
	abort "Error: The \`\`"${actionFilePath}"\`\` was missing. "
fi
ui_print "Please press the [+] or [-] key in ${defaultTimeout} seconds if you want to perform the local scanning (\`\`/data\`\`). Otherwise, you may touch the screen to skip the timing. "
startGapTime=$(date +%s%N)
keyMessage="$(getTheKeyPressed)"
keyCode=$?
endGapTime=$(date +%s%N)
gapTime=$(expr ${endGapTime} - ${startGapTime})
ui_print "${keyMessage}"
ui_print $(yes "=" | head -n ${innerSymbolCount} | tr -d '\n')
actionStrings="$(sh "${actionFilePath}" ${keyCode})"
exitCode=$?
ui_print "${actionStrings}"
ui_print $(yes "=" | head -n ${innerSymbolCount} | tr -d '\n')
if [[ ${EXIT_SUCCESS} == ${exitCode} ]];
then
	ui_print "Successfully executed the \`\`"${actionFilePath}"\`\` (${exitCode}). "
else
	ui_print "Warning: The execution of \`\`"${actionFilePath}"\`\` returned a non-zero exit code (${exitCode}). "
fi

# Finish #
readonly endTime=$(date +%s%N)
readonly timeDelta=$(expr ${endTime} - ${startTime} - ${gapTime})

setPermissions && chmod 755 "${MODPATH}"
if [[ $? -eq ${EXIT_SUCCESS} ]];
then
	ui_print "Successfully set permissions. "
else
	ui_print "Warning: Failed to set permissions. "
fi
clearCaches
if [[ $? -eq ${EXIT_SUCCESS} ]];
then
	ui_print "Successfully cleared caches. "
else
	ui_print "Warning: Failed to clear caches. "
fi
ui_print "Finished executing the \`\`customize.sh\`\` in $(expr ${timeDelta} / 1000000000).$(expr ${timeDelta} % 1000000000) second(s). "
ui_print $(yes "#" | head -n ${outerSymbolCount} | tr -d '\n')
ui_print ""
