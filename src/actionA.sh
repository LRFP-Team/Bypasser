#!/system/bin/sh
# Welcome (0b00000X) #
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
readonly actionDirectoryPath="$(dirname "$0")"
readonly adbFolder="../.."
readonly ksuFolder="${adbFolder}/ksu"
readonly magiskFolder="${adbFolder}/magisk"
readonly apatchFolder="${adbFolder}/ap"
readonly startTime=$(date +%s%N)
readonly magiskVulnerabilityVersion=27007
exitCode=${EXIT_SUCCESS}

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

echo "Welcome to the \`\`action.sh\`\` of the rooting-layer system module ${moduleName}! "
echo "The absolute path to this script slot is \"$(cd "$(dirname "$0")" && pwd)/$(basename "$0")\". "
clearCaches
if [[ $? -eq ${EXIT_SUCCESS} ]];
then
	echo "Successfully cleared caches. "
else
	exitCode=$((exitCode | ${EXIT_FAILURE}))
	echo "Failed to clear caches. "
fi
chmod 755 "${actionDirectoryPath}" && cd "${actionDirectoryPath}"
if [[ $? -eq ${EXIT_SUCCESS} && "$(basename "$(pwd)")" == "${moduleId}" ]];
then
	echo "The current working directory is \"$(pwd)\". "
	setPermissions
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		echo "Successfully set permissions. "
	else
		exitCode=$((exitCode | ${EXIT_FAILURE}))
		echo "Failed to set permissions. "
	fi
else
	echo "The working directory \"$(pwd)\" is unexpected. "
	exitCode=$((exitCode | ${EXIT_FAILURE}))
fi
androidVersion="$(getprop ro.build.version.release)"
androidVersion=${androidVersion%%.*}
if [[ "true" == "${BOOTMODE}" ]];
then
	if [[ "${KSU}" == "true" ]];
	then
		echo "KSU (${KSU_VER_CODE}): Please "
		echo "- deploy the latest ReSukiSU from the \`\`Actions\`\` tab of its GitHub repository with only applications requiring root privileges configured and granted in the ReSukiSU Manager, "
		echo "- install the latest Zygisk Next module as a system module with Denylist Policy set to Unmount Only, "
		echo "- install the latest \`\`Jing Matrix\`\` branch of the LSPosed module from the \`\`Actions\`\` tab of its GitHub repository as a system module with logging disabled and the narrowest scope configured for each plugin, "
		echo "- install the latest Play Integrity Fix (PIF) module as a system module, "
		echo "- install the latest Tricky Store (TS) module as a system module with the correct configurations, "
		echo "- install the latest Audit Patch module as a system module, and"
		if [[ ${androidVersion} -ge 12 ]];
		then
			echo "- activate the latest HMA-OSS plugin with the correct configurations and the latest FuseFixer plugin. "
		else
			echo "- activate the latest HMA-OSS plugin with the correct configurations. "
		fi
		if [[ -d "${apatchFolder}" ]];
		then
			echo "The Apatch directory exists while KSU or one of its variants is using. Please consider removing the Apatch directory. "
		fi
		if [[ -d "${magiskFolder}" ]];
		then
			echo "The Magisk directory exists while KSU or one of its variants is using. Please consider removing the Magisk directory. "
		fi
	elif [[ "${APATCH}" == "true" ]];
	then
		echo "Apatch (${APATCH_VER_CODE}): Please "
		echo "- deploy the latest Apatch from the \`\`Actions\`\` tab of its GitHub repository with only applications requiring root privileges configured and granted in the Apatch Manager, "
		echo "- embed the latest Cherish Peekaboo as a kernel module, "
		echo "- install the latest Zygisk Next module as a system module with Denylist Policy set to Unmount Only, "
		echo "- install the latest \`\`Jing Matrix\`\` branch of the LSPosed module from the \`\`Actions\`\` tab of its GitHub repository as a system module with logging disabled and the narrowest scope configured for each plugin, "
		echo "- install the latest Play Integrity Fix (PIF) module as a system module, "
		echo "- install the latest Tricky Store (TS) module as a system module with the correct configurations, "
		echo "- install the latest Audit Patch module as a system module, and"
		if [[ ${androidVersion} -ge 12 ]];
		then
			echo "- activate the latest HMA-OSS plugin with the correct configurations and the latest FuseFixer plugin. "
		else
			echo "- activate the latest HMA-OSS plugin with the correct configurations. "
		fi
		if [[ -d "${magiskFolder}" ]];
		then
			echo "The Magisk directory exists while the Apatch is using. Please consider removing the Magisk directory. "
		fi
		if [[ -d "${ksuFolder}" ]];
		then
			echo "The KSU directory exists while the Apatch is using. Please consider removing the KSU directory. "
		fi
	else
		if [[ -z "${MAGISK_VER_CODE}" ]];
		then
			MAGISK_VER_CODE="$(magisk -V)" &> /dev/null
		fi
		if [[ -z "${MAGISK_VER}" ]];
		then
			MAGISK_VER="$(magisk -v | cut -d ':' -f1)" &> /dev/null
		fi
		if [[ -n "${MAGISK_VER_CODE}" ]];
		then
			if [[ ${MAGISK_VER} == *-kitsune || ${MAGISK_VER} == *-delta ]];
			then
				echo "Magisk Delta (${MAGISK_VER_CODE}): Please "
				echo "- deploy the latest Magisk Delta with the built-in Zygisk enabled, the whitelist mode enabled, and only applications requiring root privileges configured and granted in the Magisk Delta Manager, "
				echo "- install the latest \`\`Jing Matrix\`\` branch of the LSPosed module from the \`\`Actions\`\` tab of its GitHub repository as a system module with the narrowest scope configured for each plugin, "
				echo "- install the latest Play Integrity Fix (PIF) module, "
				echo "- install the latest Tricky Store (TS) module with the correct configurations, "
				echo "- install the latest Audit Patch module, "
				echo "- install the latest bindhosts or the built-in Systemless hosts module (optional), and "
				if [[ ${androidVersion} -ge 12 ]];
				then
					echo "- activate the latest HMA-OSS plugin with the correct configurations and the latest FuseFixer plugin. "
				else
					echo "- activate the latest HMA-OSS plugin with the correct configurations. "
				fi
				echo "Please consider switching to the latest Magisk Alpha if possible. "
			else
				if [[ ${MAGISK_VER} == *-alpha ]];
				then
					echo -n "Magisk Alpha "
				elif [[ ${MAGISK_VER} == *-beta ]];
				then
					echo -n "Magisk Beta "
				elif [[ ${MAGISK_VER} == *-canary ]];
				then
					echo -n "Magisk Canary "
				else
					echo -n "Magisk "
				fi
				echo "(${MAGISK_VER_CODE}): Please "
				echo "- deploy the latest Magisk Alpha with the built-in Zygisk and denylist disabled, "
				echo "- execute applications requiring root privileges with root privileges granted, "
				echo "- install the latest Zygisk Next module with Denylist Policy set to Unmount Only, "
				echo "- install the latest \`\`Jing Matrix\`\` branch of the LSPosed module from the \`\`Actions\`\` tab of its GitHub repository with logging disabled and the narrowest scope configured for each plugin, "
				echo "- install the latest Play Integrity Fix (PIF) module, "
				echo "- install the latest Tricky Store (TS) module with the correct configurations, "
				echo "- install the latest Audit Patch module, "
				echo "- install the latest bindhosts or the built-in Systemless hosts module (optional), and "
				if [[ ${androidVersion} -ge 12 ]];
				then
					echo "- activate the latest HMA-OSS plugin with the correct configurations and the latest FuseFixer plugin. "
				else
					echo "- activate the latest HMA-OSS plugin with the correct configurations. "
				fi
			fi
			if [[ ${MAGISK_VER_CODE} -lt ${magiskVulnerabilityVersion} ]];
			then
				echo "Magisk versions before ${magiskVulnerabilityVersion} can contain severe privilege escalation vulnerability. You are using Magisk ${MAGISK_VER_CODE}. Please update it as soon as possible. "
			fi
			if [[ -d "${apatchFolder}" ]];
			then
				echo "The Apatch directory exists while the Magisk is using. Please consider removing the Apatch directory. "
			fi
			if [[ -d "${ksuFolder}" ]];
			then
				echo "The KSU directory exists while the Magisk is using. Please consider removing the KSU directory. "
			fi
		else
			echo "Unknown: The rooting solution used is unknown. "
		fi
	fi
else
	echo "Unbooted: The device is not working in the boot mode. "
fi
echo ""

# Zygisk Traces (0b0000X0) #
echo "# Zygisk Traces (0b0000X0) #"
readonly magiskModuleFolder="${adbFolder}/modules"
readonly zygiskSolutionModuleId="zygisksu"
readonly zygiskNextConfigurationDirectoryPath="${adbFolder}/zygisksu"
readonly zygiskNextDenylistEnforceConfigurationFileName="denylist_enforce"
readonly zygiskNextDenylistEnforceConfigurationFilePath="${zygiskNextConfigurationDirectoryPath}/${zygiskNextDenylistEnforceConfigurationFileName}"
readonly zygiskNextDenylistPolicyConfigurationFileName="denylist_policy"
readonly zygiskNextDenylistPolicyConfigurationFilePath="${zygiskNextConfigurationDirectoryPath}/${zygiskNextDenylistPolicyConfigurationFileName}"
readonly shamikoModuleId="zygisk_shamiko"
readonly shamikoConfigurationDirectoryPath="${adbFolder}/shamiko"
readonly shamikoWhitelistConfigurationFileName="whitelist"
readonly shamikoWhitelistConfigurationFilePath="${shamikoConfigurationDirectoryPath}/${shamikoWhitelistConfigurationFileName}"
readonly zygiskAssistantModuleId="zygisk-assistant"
readonly noHelloModuleId="zygisk_nohello"
readonly noHelloConfigurationDirectoryPath="${adbFolder}/nohello"
readonly noHelloWhitelistConfigurationFileName="whitelist"
readonly noHelloWhitelistConfigurationFilePath="${noHelloConfigurationDirectoryPath}/${noHelloWhitelistConfigurationFileName}"
readonly rezygiskConfigurationDirectoryPath="${adbFolder}/rezygisk"
readonly neozygiskConfigurationDirectoryPath="${adbFolder}/neozygisk"
readonly builtInZygiskFilePath="${adbFolder}/magisk/zygisk"

function isModuleInstalled
{
	moduleInstallationDirectoryPath="${magiskModuleFolder}/$1"
	if [[ -d "${moduleInstallationDirectoryPath}" ]];
	then
		modulePropFileName="module.prop"
		modulePropFilePath="${moduleInstallationDirectoryPath}/${modulePropFileName}"
		if [[ -f "${modulePropFilePath}" ]];
		then
			if grep -q "^id=$1\$" "${modulePropFilePath}";
			then
				grep "^name=" "${modulePropFilePath}" | cut -d '=' -f2
				return ${EXIT_SUCCESS}
			fi
		fi
	fi
	return ${EXIT_FAILURE}
}

if [[ "${ZYGISK_ENABLED}" == "1" ]];
then
	zygiskSolutionModuleName="$(isModuleInstalled "${zygiskSolutionModuleId}")"
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		echo "The Zygisk solution was implemented by ${zygiskSolutionModuleName}. "
		toBeWritten="2"
		if isModuleInstalled "${shamikoModuleId}" > /dev/null;
		then
			toBeWritten="0"
			echo "The Shamiko module was installed. "
			if [[ "${APATCH}" == "true" ]];
			then
				echo "Please kindly acknowledge that the Shamiko module does not work with Apatch. Please consider using ReZygisk + NoHello in Apatch. "
			elif [[ ${MAGISK_VER} == *-kitsune || ${MAGISK_VER} == *-delta ]];
			then
				echo "Please kindly acknowledge that the Shamiko module does not work with Magisk Delta. Please consider switching to Magisk Alpha or removing the Shamiko module. "
			fi
			mkdir -p "${shamikoConfigurationDirectoryPath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -d "${shamikoConfigurationDirectoryPath}" ]];
			then
				echo "Successfully prepared the Shamiko configuration directory \"${shamikoConfigurationDirectoryPath}\". "
				if [[ -f "${shamikoWhitelistConfigurationFilePath}" ]];
				then
					echo "The Shamiko whitelist configuration file \"${shamikoWhitelistConfigurationFilePath}\" already existed. "
				else
					echo "The Shamiko whitelist configuration file \"${shamikoWhitelistConfigurationFilePath}\" did not exist. "
					touch "${shamikoWhitelistConfigurationFilePath}"
					if [[ $? -eq ${EXIT_SUCCESS} && -f "${shamikoWhitelistConfigurationFilePath}" ]];
					then
						echo "Successfully created the Shamiko whitelist configuration file \"${shamikoWhitelistConfigurationFilePath}\". "
					else
						exitCode=$((exitCode | 2))
						echo "Failed to create the Shamiko whitelist configuration file \"${shamikoWhitelistConfigurationFilePath}\". "
					fi
				fi
			else
				echo "Failed to prepare the Shamiko configuration directory \"${shamikoConfigurationDirectoryPath}\". "
			fi
		else
			echo "The Shamiko module was not installed. "
		fi
		if isModuleInstalled "${zygiskAssistantModuleId}" > /dev/null;
		then
			if [[ "0" == "${toBeWritten}" ]];
			then
				if [[ "${APATCH}" != "true" && ${MAGISK_VER} != *-kitsune && ${MAGISK_VER} != *-delta ]];
				then
					echo "The Zygisk Assistant module was installed while the Shamiko module was installed. Please consider only using the Shamiko module in your environment. "
				else
					echo "The Zygisk Assistant module was installed while the Shamiko module was installed. Please consider only using the Zygisk Assistant module in your environment. "
				fi
			else
				echo "The Zygisk Assistant module was installed. "
			fi
		else
			echo "The Zygisk Assistant module was not installed. "
		fi
		if isModuleInstalled "${noHelloModuleId}" > /dev/null;
		then
			if [[ "0" == "${toBeWritten}" ]];
			then
				if [[ "${APATCH}" != "true" && ${MAGISK_VER} != *-kitsune && ${MAGISK_VER} != *-delta ]];
				then
					echo "The NoHello module was installed while the Shamiko or the Zygisk Assistant module was installed, which can cause compatibility issues. Please consider only using the Shamiko module in your environment. "
				else
					echo "The NoHello module was installed while the Shamiko or the Zygisk Assistant module was installed, which can cause compatibility issues. Please consider only using the NoHello module in your environment. "
				fi
			else
				echo "The NoHello module was installed. "
			fi
			mkdir -p "${noHelloConfigurationDirectoryPath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -d "${noHelloConfigurationDirectoryPath}" ]];
			then
				echo "Successfully prepared the NoHello configuration directory \"${noHelloConfigurationDirectoryPath}\". "
				if [[ -f "${noHelloWhitelistConfigurationFilePath}" ]];
				then
					echo "The NoHello whitelist configuration file \"${noHelloWhitelistConfigurationFilePath}\" already existed. "
				else
					echo "The NoHello whitelist configuration file \"${noHelloWhitelistConfigurationFilePath}\" did not exist. "
					touch "${noHelloWhitelistConfigurationFilePath}"
					if [[ $? -eq ${EXIT_SUCCESS} && -f "${noHelloWhitelistConfigurationFilePath}" ]];
					then
						echo "Successfully created the NoHello whitelist configuration file \"${noHelloWhitelistConfigurationFilePath}\". "
					else
						exitCode=$((exitCode | 2))
						echo "Failed to create the NoHello whitelist configuration file \"${noHelloWhitelistConfigurationFilePath}\". "
					fi
				fi
			else
				echo "Failed to prepare the NoHello configuration directory \"${noHelloConfigurationDirectoryPath}\". "
			fi
		else
			echo "The NoHello module was not installed. "
		fi
		if [[ "Zygisk Next" == "${zygiskSolutionModuleName}" ]];
		then
			mkdir -p "${zygiskNextConfigurationDirectoryPath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -d "${zygiskNextConfigurationDirectoryPath}" ]];
			then
				echo "Successfully prepared the Zygisk Next configuration directory \"${zygiskNextConfigurationDirectoryPath}\". "
				if [[ -f "${zygiskNextDenylistPolicyConfigurationFilePath}" && "1" == "$(cat "${zygiskNextDenylistPolicyConfigurationFilePath}")" ]];
				then
					echo "The Zygisk Next denylist policy configuration file \"${zygiskNextDenylistPolicyConfigurationFilePath}\" is already configured. "
				else
					echo "The Zygisk Next denylist policy configuration file \"${zygiskNextDenylistPolicyConfigurationFilePath}\" was not configured. "
					echo -n "1" > "${zygiskNextDenylistPolicyConfigurationFilePath}"
					if [[ $? -eq ${EXIT_SUCCESS} && -f "${zygiskNextDenylistPolicyConfigurationFilePath}" ]];
					then
						echo "Successfully wrote \"1\" to the Zygisk Next denylist policy configuration file \"${zygiskNextDenylistPolicyConfigurationFilePath}\". "
					else
						exitCode=$((exitCode | 2))
						echo "Failed to write \"1\" to the Zygisk Next denylist policy configuration file \"${zygiskNextDenylistPolicyConfigurationFilePath}\". "
					fi
				fi
				if [[ -f "${zygiskNextDenylistEnforceConfigurationFilePath}" && "${toBeWritten}" == "$(cat "${zygiskNextDenylistEnforceConfigurationFilePath}")" ]];
				then
					echo "The Zygisk Next denylist enforce configuration file \"${zygiskNextDenylistEnforceConfigurationFilePath}\" is already configured. "
				else
					echo "The Zygisk Next denylist enforce configuration file \"${zygiskNextDenylistEnforceConfigurationFilePath}\" was not configured. "
					echo -n "${toBeWritten}" > "${zygiskNextDenylistEnforceConfigurationFilePath}"
					if [[ $? -eq ${EXIT_SUCCESS} && -f "${zygiskNextDenylistEnforceConfigurationFilePath}" ]];
					then
						echo "Successfully wrote \"${toBeWritten}\" to the Zygisk Next denylist enforce configuration file \"${zygiskNextDenylistEnforceConfigurationFilePath}\". "
					else
						exitCode=$((exitCode | 2))
						echo "Failed to write \"${toBeWritten}\" to the Zygisk Next denylist enforce configuration file \"${zygiskNextDenylistEnforceConfigurationFilePath}\". "
					fi
				fi
			else
				echo "Failed to prepare the Zygisk Next configuration directory \"${zygiskNextConfigurationDirectoryPath}\". "
			fi
			if [[ -d "${rezygiskConfigurationDirectoryPath}" ]];
			then
				echo "The ReZygisk configuration directory exists while the Zygisk Next is using. Please consider removing the ReZygisk configuration directory. "
			fi
			if [[ -d "${neozygiskConfigurationDirectoryPath}" ]];
			then
				echo "The NeoZygisk configuration directory exists while the Zygisk Next is using. Please consider removing the NeoZygisk configuration directory. "
			fi
		elif [[ "ReZygisk" == "${zygiskSolutionModuleName}" ]];
		then
			if [[ -d "${zygiskNextConfigurationDirectoryPath}" ]];
			then
				echo "The Zygisk Next configuration directory exists while the ReZygisk is using. Please consider removing the Zygisk Next configuration directory. "
			fi
			if [[ -d "${neozygiskConfigurationDirectoryPath}" ]];
			then
				echo "The NeoZygisk configuration directory exists while the ReZygisk is using. Please consider removing the NeoZygisk configuration directory. "
			fi
		elif [[ "NeoZygisk" == "${zygiskSolutionModuleName}" ]];
		then
			if [[ -d "${zygiskNextConfigurationDirectoryPath}" ]];
			then
				echo "The Zygisk Next configuration directory exists while the NeoZygisk is using. Please consider removing the Zygisk Next configuration directory. "
			fi
			if [[ -d "${rezygiskConfigurationDirectoryPath}" ]];
			then
				echo "The ReZygisk configuration directory exists while the NeoZygisk is using. Please consider removing the ReZygisk configuration directory. "
			fi
			if isModuleInstalled "${shamikoModuleId}" > /dev/null;
			then
				if [[ "${APATCH}" == "true" ]];
				then
					echo "The Shamiko module does not work with Apatch or NeoZygisk. Please consider removing this module and switching to ReZygisk + NeHello. "
				else
					echo "The Shamiko module does not work with NeoZygisk. Please consider either switching to Zygisk Next or removing this module. "
				fi
			fi
			if isModuleInstalled "${noHelloModuleId}" > /dev/null;
			then
				echo "The NoHello module does not work with NeoZygisk. Please consider either switching to ReZygisk or removing this module. "
			fi
		fi
	elif [[ -f "${builtInZygiskFilePath}" ]]
	then
		echo "The Zygisk solution was implemented by Magisk built-in Zygisk. "
	else
		echo "The Zygisk was enabled but the implementation was unknown. "
	fi
else
	echo "The Zygisk was not enabled. "
fi
echo ""

# HMA Configurations (0b000X00) #
echo "# HMA Configurations (0b000X00) #"
readonly webrootName="webroot"
readonly curlTimeout=10
readonly webrootDigestUrl="https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/src/${webrootName}.zip.sha512"
readonly webrootDirectoryPath="${webrootName}"
readonly downloadTimeout=30
readonly webrootUrl="https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/src/${webrootName}.zip"
readonly webrootFilePath="${webrootName}.zip"
readonly currentAB="A"
readonly targetAB="B"
readonly actionPropFileName="action.prop"
readonly actionPropFilePath="${webrootDirectoryPath}/${actionPropFileName}"
readonly databaseFileName="database.json"
readonly databaseFilePath="${webrootDirectoryPath}/${databaseFileName}"
readonly cppBinaryFileName="generate"
readonly cppBinaryFilePath="${webrootDirectoryPath}/${cppBinaryFileName}_$(getprop ro.product.cpu.abi)"
if [[ -n "${EXTERNAL_STORAGE}" ]];
then
	readonly generationOutputDirectoryPath="${EXTERNAL_STORAGE}/Download/.${moduleName}"
else
	readonly generationOutputDirectoryPath="/sdcard/Download/.${moduleName}"
fi
readonly hmaV92WhitelistConfigurationFileName=".hmaV92WhitelistConfiguration.json"
readonly hmaV92WhitelistConfigurationFilePath="${generationOutputDirectoryPath}/${hmaV92WhitelistConfigurationFileName}"
readonly hmaV92BlacklistConfigurationFileName=".hmaV92BlacklistConfiguration.json"
readonly hmaV92BlacklistConfigurationFilePath="${generationOutputDirectoryPath}/${hmaV92BlacklistConfigurationFileName}"
readonly hmaV93WhitelistConfigurationFileName=".hmaV93WhitelistConfiguration.json"
readonly hmaV93WhitelistConfigurationFilePath="${generationOutputDirectoryPath}/${hmaV93WhitelistConfigurationFileName}"
readonly hmaV93BlacklistConfigurationFileName=".hmaV93BlacklistConfiguration.json"
readonly hmaV93BlacklistConfigurationFilePath="${generationOutputDirectoryPath}/${hmaV93BlacklistConfigurationFileName}"
readonly hmaossV93WhitelistConfigurationFileName=".hmaossV93WhitelistConfiguration.json"
readonly hmaossV93WhitelistConfigurationFilePath="${generationOutputDirectoryPath}/${hmaossV93WhitelistConfigurationFileName}"
readonly hmaossV93BlacklistConfigurationFileName=".hmaossV93BlacklistConfiguration.json"
readonly hmaossV93BlacklistConfigurationFilePath="${generationOutputDirectoryPath}/${hmaossV93BlacklistConfigurationFileName}"
readonly pathTesterFileName=".pathTester.sh"
readonly pathTesterFilePath="${generationOutputDirectoryPath}/${pathTesterFileName}"
readonly largerOldScanningScope="/data"
readonly smallerOldScanningScope="/data/misc"
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

webrootDigest="$(curl -sSfL -m ${curlTimeout} "${webrootDigestUrl}")"
if [[ $? -eq ${EXIT_SUCCESS} && -n "${webrootDigest}" ]];
then
	echo "Successfully fetched the SHA-512 value of the latest ZIP file of the web UI. "
	if [[ -d "${webrootDirectoryPath}" && "$(find "${webrootDirectoryPath}" -type f ! -name "*.sha512" ! -name "*.prop" -exec sha512sum {} \; | sort)" == "${webrootDigest}" ]];
	then
		echo "The current web UI is already up-to-date. "
	else
		echo "The current web UI is out-of-date and needs to be updated. "
		abortFlag=${EXIT_SUCCESS}
		if [[ -d "${webrootDirectoryPath}" ]];
		then
			rm -rf "${webrootDirectoryPath}.bak" && mv -fT "${webrootDirectoryPath}" "${webrootDirectoryPath}.bak"
			if [[ $? -eq ${EXIT_SUCCESS} && -d "${webrootDirectoryPath}.bak" ]];
			then
				echo "Successfully moved \"${webrootDirectoryPath}\" to \"${webrootDirectoryPath}.bak\". "
			else
				abortFlag=${EXIT_FAILURE}
				exitCode=$((exitCode | 32))
				echo "Failed to move \"${webrootDirectoryPath}\" to \"${webrootDirectoryPath}.bak\". "
			fi
		else
			echo "No old web UI directories were found to be backed up. "
		fi
		if [[ ${EXIT_SUCCESS} -eq ${abortFlag} ]];
		then
			echo "Trying to download the latest web UI within ${downloadTimeout} seconds. "
			curl -sSfL --connect-timeout ${curlTimeout} -m ${downloadTimeout} "${webrootUrl}" -o "${webrootFilePath}" && unzip "${webrootFilePath}" -d "${webrootDirectoryPath}" && rm -f "${webrootFilePath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -d "${webrootDirectoryPath}" && "$(find "${webrootDirectoryPath}" -type f ! -name "*.sha512" ! -name "*.prop" -exec sha512sum {} \; | sort)" == "${webrootDigest}" ]];
			then
				echo "Successfully updated and verified the web UI. "
				if [[ -d "${webrootDirectoryPath}.bak" ]];
				then
					rm -f "${actionPropFilePath}" && echo -n "${currentAB}" > "${actionPropFilePath}"
					if [[ $? -eq ${EXIT_SUCCESS} && ! -e "${webrootDirectoryPath}.bak" ]];
					then
						echo "Successfully restored the action slot \"${currentAB}\". "
						rm -rf "${webrootDirectoryPath}.bak"
						if [[ $? -eq ${EXIT_SUCCESS} && ! -e "${webrootDirectoryPath}.bak" ]];
						then
							echo "Successfully removed \"${webrootDirectoryPath}.bak\". "
						else
							echo "Failed to remove \"${webrootDirectoryPath}.bak\". "
						fi
					else
						echo "Failed to restore the action slot \"${currentAB}\". "
					fi
				else
					echo "No old web UI directories that should be removed were found. "
				fi
			else
				exitCode=$((exitCode | 32))
				echo "Failed to update or verify the web UI. "
				if [[ -d "${webrootDirectoryPath}.bak" ]];
				then
					rm -rf "${webrootDirectoryPath}" && mv -fT "${webrootDirectoryPath}.bak" "${webrootDirectoryPath}"
					if [[ $? -eq ${EXIT_SUCCESS} && -d "${webrootDirectoryPath}" ]];
					then
						echo "Successfully restored \"${webrootDirectoryPath}.bak\" to \"${webrootDirectoryPath}\". "
					else
						echo "Failed to restore \"${webrootDirectoryPath}.bak\" to \"${webrootDirectoryPath}\". "
					fi
				else
					echo "No old web UI directories were found for restoring. "
				fi
			fi
		fi
	fi
else
	exitCode=$((exitCode | 32))
	echo "Failed to fetch the SHA-512 value of the latest ZIP file of the web UI. "
fi
if [[ $((exitCode & 32)) -ne ${EXIT_SUCCESS} ]];
then
	echo "The updating of the \`\`${databaseFileName}\`\` might fail. This will use the cache to generate the configurations for HMA and its variants. "
fi
mkdir -p "${generationOutputDirectoryPath}"
if [[ $? -eq ${EXIT_SUCCESS} && -d "${generationOutputDirectoryPath}" ]];
then
	echo "Successfully prepared the directory \"${generationOutputDirectoryPath}\". "
	chmod u+x "${cppBinaryFilePath}"
	trickyStoreTargetContent="$("${cppBinaryFilePath}" -i "${databaseFilePath}" -l "Info" -oa92w "${hmaV92WhitelistConfigurationFilePath}" -oa92b "${hmaV92BlacklistConfigurationFilePath}" -oa93w "${hmaV93WhitelistConfigurationFilePath}" -oa93b "${hmaV93BlacklistConfigurationFilePath}" -os93w "${hmaossV93WhitelistConfigurationFilePath}" -os93b "${hmaossV93BlacklistConfigurationFilePath}" -op "${pathTesterFilePath}" -ot .)"
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		if [[ -f "${hmaV92WhitelistConfigurationFilePath}" ]];
		then
			echo "Successfully generated the HMA v92 whitelist configuration JSON file \"${hmaV92WhitelistConfigurationFilePath}\". "
		else
			exitCode=$((exitCode | 4))
			echo "Failed to generate the HMA v92 whitelist configuration JSON file \"${hmaV92WhitelistConfigurationFilePath}\". "
		fi
		if [[ -f "${hmaV92BlacklistConfigurationFilePath}" ]];
		then
			echo "Successfully generated the HMA v92 blacklist configuration JSON file \"${hmaV92BlacklistConfigurationFilePath}\". "
		else
			exitCode=$((exitCode | 4))
			echo "Failed to generate the HMA v92 blacklist configuration JSON file \"${hmaV92BlacklistConfigurationFilePath}\". "
		fi
		if [[ -f "${hmaV93WhitelistConfigurationFilePath}" ]];
		then
			echo "Successfully generated the HMA v93 whitelist configuration JSON file \"${hmaV93WhitelistConfigurationFilePath}\". "
		else
			exitCode=$((exitCode | 4))
			echo "Failed to generate the HMA v93 whitelist configuration JSON file \"${hmaV93WhitelistConfigurationFilePath}\". "
		fi
		if [[ -f "${hmaV93BlacklistConfigurationFilePath}" ]];
		then
			echo "Successfully generated the HMA v93 blacklist configuration JSON file \"${hmaV93BlacklistConfigurationFilePath}\". "
		else
			exitCode=$((exitCode | 4))
			echo "Failed to generate the HMA v93 blacklist configuration JSON file \"${hmaV93BlacklistConfigurationFilePath}\". "
		fi
		if [[ -f "${hmaossV93WhitelistConfigurationFilePath}" ]];
		then
			echo "Successfully generated the HMA-OSS v93 whitelist configuration JSON file \"${hmaossV93WhitelistConfigurationFilePath}\". "
		else
			exitCode=$((exitCode | 4))
			echo "Failed to generate the HMA-OSS v93 whitelist configuration JSON file \"${hmaossV93WhitelistConfigurationFilePath}\". "
		fi
		if [[ -f "${hmaossV93BlacklistConfigurationFilePath}" ]];
		then
			echo "Successfully generated the HMA-OSS v93 blacklist configuration JSON file \"${hmaossV93BlacklistConfigurationFilePath}\". "
		else
			exitCode=$((exitCode | 4))
			echo "Failed to generate the HMA-OSS v93 blacklist configuration JSON file \"${hmaossV93BlacklistConfigurationFilePath}\". "
		fi
		if [[ -f "${pathTesterFilePath}" ]];
		then
			echo "Successfully generated the path tester shell script file \"${pathTesterFilePath}\". "
		else
			exitCode=$((exitCode | 4))
			echo "Failed to generate the path tester shell script file \"${pathTesterFilePath}\". "
		fi
	else
		exitCode=$((exitCode | 4))
		echo "Failed to generate relevant files for HMA and its variants. "
	fi
	chmod -x "${cppBinaryFilePath}"
else
	exitCode=$((exitCode | 4))
	echo "Failed to prepare the directory \"${generationOutputDirectoryPath}\". "
fi
if [[ $# -ge 1 ]];
then
	keyCode="$1"
else
	echo "Please press the [+] or [-] key in ${defaultTimeout} seconds if you want to perform the local scanning (\`\`/data\`\`). Otherwise, you may touch the screen to skip the timing. "
	startGapTime=$(date +%s%N)
	getTheKeyPressed
	keyCode=$?
	endGapTime=$(date +%s%N)
	gapTime=$((endGapTime - startGapTime))
fi
if [[ ${VK_UP} -eq ${keyCode} || ${VK_DOWN} -eq ${keyCode} ]];
then
	oldConfigurationFolderCount=0
	removedOldConfigurationFolderCount=0
	echo "Removing old configuration directories of HMA and its variants. "
	for oldConfigurationDirectoryPath in $(find "${largerOldScanningScope}" -type d -and \( -name "*h_m_a_l*" -or -name "*hma*" -or -name "*hma1*" -or -name "hmal*" \))
	do
		if [[ -e "${oldConfigurationDirectoryPath}/config.json" && -d "${oldConfigurationDirectoryPath}/log" ]];
		then
			oldConfigurationFolderCount=$((oldConfigurationFolderCount + 1))
			if rm -rf "${oldConfigurationDirectoryPath}";
			then
				removedOldConfigurationFolderCount=$((removedOldConfigurationFolderCount + 1))
				echo "[${removedOldConfigurationFolderCount}/${oldConfigurationFolderCount}] Successfully removed \"${oldConfigurationDirectoryPath}\" (L). "
			else
				echo "[${removedOldConfigurationFolderCount}/${oldConfigurationFolderCount}] Failed to remove \"${oldConfigurationDirectoryPath}\" (L). "
			fi
		fi
	done
	for oldConfigurationDirectoryPath in $(find "${smallerOldScanningScope}" -mindepth 2 -type d -and \( -name "*h_m_a_l*" -or -name "*hma*" -or -name "*hma1*" -or -name "hmal*" \))
	do
		if [[ -z "$(ls -A "${oldConfigurationDirectoryPath}")" ]];
		then
			oldConfigurationFolderCount=$((oldConfigurationFolderCount + 1))
			if rm -rf "${oldConfigurationDirectoryPath}";
			then
				removedOldConfigurationFolderCount=$((removedOldConfigurationFolderCount + 1))
				echo "[${removedOldConfigurationFolderCount}/${oldConfigurationFolderCount}] Successfully removed \"${oldConfigurationDirectoryPath}\" (S). "
			else
				echo "[${removedOldConfigurationFolderCount}/${oldConfigurationFolderCount}] Failed to remove \"${oldConfigurationDirectoryPath}\" (S). "
			fi
		fi
	done
	if [[ ${oldConfigurationFolderCount} -ge 2 ]];
	then
		echo "Found ${oldConfigurationFolderCount} old configuration directories of HMA and its variants in the \"${largerOldScanningScope}\" directory, with ${removedOldConfigurationFolderCount} removed successfully. "
	elif [[ ${oldConfigurationFolderCount} -eq 1 ]];
	then
		echo "Found 1 old configuration directory of HMA or its variants in the \"${largerOldScanningScope}\" directory, with ${removedOldConfigurationFolderCount} removed successfully. "
	else
		echo "No old configuration directories of HMA or its variants were found. "
	fi
fi
echo ""

# Tricky Store (0b00X000) #
echo "# Tricky Store (0b00X000) #"
readonly trickyStoreConfigurationDirectoryPath="${adbFolder}/tricky_store"
readonly trickyStoreSecurityPatchFileName="security_patch.txt"
readonly trickyStoreSecurityPatchFilePath="${trickyStoreConfigurationDirectoryPath}/${trickyStoreSecurityPatchFileName}"
readonly trickyStoreTargetFileName="target.txt"
readonly trickyStoreTargetFilePath="${trickyStoreConfigurationDirectoryPath}/${trickyStoreTargetFileName}"

if [[ -d "${trickyStoreConfigurationDirectoryPath}" ]];
then
	echo "The Tricky Store configuration directory was found at \"${trickyStoreConfigurationDirectoryPath}\". "
	if [[ -f "${trickyStoreSecurityPatchFilePath}" ]];
	then
		echo "The security patch file was found at \"${trickyStoreSecurityPatchFilePath}\". "
		if mv -f "${trickyStoreSecurityPatchFilePath}" "${trickyStoreSecurityPatchFilePath}.bak";
		then
			echo "Successfully removed \"${trickyStoreSecurityPatchFilePath}\" by renaming to \`\`${trickyStoreSecurityPatchFileName}.bak\`\`. "
		else
			exitCode=$((exitCode | 8))
			echo "Failed to remove \"${trickyStoreSecurityPatchFilePath}\" by renaming to \`\`${trickyStoreSecurityPatchFileName}.bak\`\`. "
		fi
	else
		echo "The security patch file at \"${trickyStoreSecurityPatchFilePath}\" did not exist, which was proper. "
	fi
	abortFlag=${EXIT_SUCCESS}
	if [[ -f "${trickyStoreTargetFilePath}" ]];
	then
		echo "The Tricky Store target file was found at \"${trickyStoreTargetFilePath}\". "
		mv -f "${trickyStoreTargetFilePath}" "${trickyStoreTargetFilePath}.bak"
		if [[ $? -eq ${EXIT_SUCCESS} && -f "${trickyStoreTargetFilePath}.bak" ]];
		then
			echo "Successfully moved \"${trickyStoreTargetFilePath}\" to \"${trickyStoreTargetFilePath}.bak\". "
		else
			abortFlag=${EXIT_FAILURE}
			echo "Failed to move \"${trickyStoreTargetFilePath}\" to \"${trickyStoreTargetFilePath}.bak\". "
		fi
	else
		echo "The backing up has been skipped since the Tricky Store target text file \"${trickyStoreTargetFilePath}\" did not exist. "
	fi
	if [[ ${EXIT_SUCCESS} -eq ${abortFlag} ]];
	then
		echo -n "${trickyStoreTargetContent}" > "${trickyStoreTargetFilePath}"
		if [[ $? -eq ${EXIT_SUCCESS} && -f "${trickyStoreTargetFilePath}" ]];
		then
			echo "Successfully generated \"${trickyStoreTargetFilePath}\". "
		else
			echo "Failed to generate \"${trickyStoreTargetFilePath}\". "
			if [[ -f "${trickyStoreTargetFilePath}.bak" ]];
			then
				if rm -f "${trickyStoreTargetFilePath}" && mv -f "${trickyStoreTargetFilePath}.bak" "${trickyStoreTargetFilePath}";
				then
					echo "Successfully restored \"${trickyStoreTargetFilePath}.bak\" to \"${trickyStoreTargetFilePath}\". "
				else
					echo "Failed to restore \"${trickyStoreTargetFilePath}.bak\" to \"${trickyStoreTargetFilePath}\". "
				fi
			else
				echo "The backup file \"${trickyStoreTargetFilePath}.bak\" does not exist. "
			fi
		fi
	fi
else
	echo "The Tricky Store configuration directory did not exist. "
fi
echo ""

# Shell (0b0X0000) #
echo "# Shell (0b0X0000) #"
readonly sensitiveApplications="com.google.android.safetycore com.google.android.contactkeys"
readonly policiesToBeDeleted="hidden_api_policy hidden_api_policy_p_apps hidden_api_policy_pre_p_apps hidden_api_blacklist_exemptions"
readonly propertiesToBeSet="ro.boot.vbmeta.device_state:locked ro.boot.verifiedbootstate:green vendor.boot.secboot:enabled"
readonly propertiesToExist="ro.boot.vbmeta.avb_version ro.boot.vbmeta.hash_alg ro.boot.vbmeta.size ro.boot.vbmeta.digest"
readonly propertiesToBeDeleted="persist.sys.vold_app_data_isolation_enabled persist.zygote.app_data_isolation ro.oem_unlock_supported"
readonly persistentPropertyFilePath="/data/property/persistent_properties"
readonly bannedSubStrings="-AICP -arter97 -blu_spark -CAF -cm- -crDroid -crdroid -CyanogenMod -Deathly -EAS- -eas- -ElementalX -Elite -franco -hadesKernel -Lineage- -lineage- -LineageOS -lineageos -mokee -MoRoKernel -Noble -Optimus -SlimRoms -Sultan -sultan"
readonly sourceXmlFilePath="/etc/compatconfig/services-platform-compat-config.xml"
readonly replacementEntry="system"
readonly targetXmlFilePath="${replacementEntry}${sourceXmlFilePath}"

echo "The sensitive applications are being handled. "
sensitiveApplicationCount=0
disabledSensitiveApplicationCount=0
packageList="$(pm list packages)"
for sensitiveApplication in ${sensitiveApplications}
do
	if echo "${packageList}" | grep -qF "${sensitiveApplication}";
	then
		sensitiveApplicationCount=$((sensitiveApplicationCount + 1))
		if pm disable "${sensitiveApplication}" &> /dev/null;
		then
			disabledSensitiveApplicationCount=$((disabledSensitiveApplicationCount + 1))
			echo "- The sensitive application \"${sensitiveApplication}\" was detected, which has been disabled. "
		else
			exitCode=$((exitCode | 16))
			echo "- The sensitive application \"${sensitiveApplication}\" was detected, which failed to be disabled. "
		fi
	fi
done
if [[ ${sensitiveApplicationCount} -ge 1 ]];
then
	echo "Successfully disabled ${disabledSensitiveApplicationCount} / ${sensitiveApplicationCount} sensitive application(s). "
else
	echo "No sensitive applications were found. "
fi
echo "The policies are being handled. "
for policyToBeDeleted in ${policiesToBeDeleted}
do
	executionContent="$(settings delete global ${policyToBeDeleted})"
	if [[ $? -eq ${EXIT_SUCCESS} && "${executionContent}" == "Deleted 0 rows" ]];
	then
		echo "- The execution of \`\`settings delete global ${policyToBeDeleted}\`\` succeeded. "
	else
		exitCode=$((exitCode | 16))
		echo "- The execution of \`\`settings delete global ${policyToBeDeleted}\`\` failed. "
	fi
done
echo "The properties are being handled. "
for propertyKeyValue in ${propertiesToBeSet}
do
	propertyKey="$(echo "${propertyKeyValue}" | cut -d ':' -f1)"
	propertyValue="$(echo "${propertyKeyValue}" | cut -d ':' -f2)"
	executionContent="$(getprop "${propertyKey}")"
	if [[ $? -eq ${EXIT_SUCCESS} && "${executionContent}" == "${propertyValue}" ]];
	then
		echo "- The value of \`\`${propertyKey}\`\` was \"${executionContent}\", which was proper. "
	else
		resetprop "${propertyKey}" "${propertyValue}"
		if [[ $? -eq ${EXIT_SUCCESS} && "$(getprop "${propertyKey}")" == "${propertyValue}" ]];
		then
			echo "- The value of \`\`${propertyKey}\`\` was \"${executionContent}\", which should be and successfully set to \"${propertyValue}\". "
		else
			echo "- The value of \`\`${propertyKey}\`\` was \"${executionContent}\", which should be but failed to set to \"${propertyValue}\". "
			exitCode=$((exitCode | 16))
		fi
	fi
done
propertyToExistFlag=${EXIT_SUCCESS}
for propertyToExist in ${propertiesToExist}
do
	if ! getprop "${propertyToExist}" | grep -qE "[A-Za-z0-9_-]";
	then
		propertyToExistFlag=${EXIT_FAILURE}
		echo "- The property \"${propertyToExist}\" did not exist or its value was empty, which was abnormal. "
	fi
done
for propertyToBeDeleted in ${propertiesToBeDeleted}
do
	resetprop --delete "${propertyToBeDeleted}"
	if getprop "${propertyToBeDeleted}" | grep -qE "[A-Za-z0-9_-]";
	then
		exitCode=$((exitCode | 16))
		echo "- The execution of \`\`resetprop --delete \"${propertyToBeDeleted}\"\`\` failed. "
	fi
done
if [[ -f "${persistentPropertyFilePath}" ]];
then
	sed -i '/persist\.sys\.vold_app_data_isolation_enabled/d; /persist\.zygote\.app_data_isolation/d' "${persistentPropertyFilePath}"
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		echo "- Successfully removed persistent property traces from \"${persistentPropertyFilePath}\". "
	else
		exitCode=$((exitCode | 16))
		echo "- Failed to remove persistent property traces from \"${persistentPropertyFilePath}\". "
	fi
else
	echo "- The persistent property file \"${persistentPropertyFilePath}\" did not exist. "
fi
if [[ ${propertyToExistFlag} -eq ${EXIT_FAILURE} ]];
then
	if [[ "${KSU}" == "true" || "${APATCH}" == "true" ]];
	then
		echo "Missing properties, please install the latest [VBMeta Fixer](https://github.com/reveny/Android-VBMeta-Fixer) module as a system module. "
	else
		echo "Missing properties, please install the latest [VBMeta Fixer](https://github.com/reveny/Android-VBMeta-Fixer) module. "
	fi
fi
if [[ "$(getenforce)" == "Enforcing" ]];
then
	echo "SELinux is already Enforcing. "
else
	setenforce enforcing
	if [[ $? -eq ${EXIT_SUCCESS} && "$(getenforce)" == "Enforcing" ]];
	then
		echo "SELinux was not Enforcing, which has been set to Enforcing. "
	else
		echo "SELinux is not Enforcing and cannot be set to Enforcing. "
	fi
fi
bannedSubStringFoundFlag=${EXIT_SUCCESS}
kernelVersion="$(uname -r)"
for bannedSubString in ${bannedSubStrings}
do
	if [[ "${kernelVersion}" == *"${bannedSubString}"* ]];
	then
		bannedSubStringFoundFlag=${EXIT_FAILURE}
		echo "Found the banned substring \"${bannedSubString}\" in the kernel version \"${kernelVersion}\". "
		break
	fi
done
if [[ ${bannedSubStringFoundFlag} -eq ${EXIT_SUCCESS} ]];
then
	echo "No banned substrings were found in the kernel version \"${kernelVersion}\". "
fi
if [[ -s "${sourceXmlFilePath}" ]];
then
	if grep -qF 'enableAfterTargetSdk="0" id="143937733"' "${sourceXmlFilePath}";
	then
		echo "The current \"${sourceXmlFilePath}\" is already a replaced one. "
	else
		echo "Generating replacement, the \"${sourceXmlFilePath}\" will be replaced after the device reboots. "
		targetXmlDirectoryPath="$(dirname "${targetXmlFilePath}")"
		if mkdir -p "${targetXmlDirectoryPath}";
		then
			echo "Successfully created the directory \"${targetXmlDirectoryPath}\". "
			toBeWritten=$(sed -E 's/(enableAfterTargetSdk=")[0-9]+(" id="143937733")/\10\2/g' "${sourceXmlFilePath}")
			echo -n "${toBeWritten}" > "${targetXmlFilePath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -f "${targetXmlFilePath}" ]];
			then
				echo "Successfully generated \"${targetXmlFilePath}\". "
			else
				exitCode=$((exitCode | 16))
				echo "Failed to generate \"${targetXmlFilePath}\". "
			fi
		else
			exitCode=$((exitCode | 16))
			echo "Failed to create the directory \"${targetXmlDirectoryPath}\". "
		fi
	fi
else
	echo "The \"${sourceXmlFilePath}\" did not exist or was found to be empty. "
	rm -rf "${replacementEntry}" && mkdir -p "${replacementEntry}"
	if [[ $? -eq ${EXIT_SUCCESS} && -d "${replacementEntry}" ]];
	then
		echo "Successfully removed replacement in this module. "
	else
		echo "Failed to remove replacement in this module. "
	fi
fi
if [[ ${androidVersion} -ge 10 ]];
then
	settings put global show_hidden_icon_apps_enabled 0
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		echo "Successfully enabled the feature of hiding desktop icons (Android ${androidVersion}). "
	else
		echo "Failed to enable the feature of hiding desktop icons (Android ${androidVersion}). "
	fi
fi
echo ""

# Update (0bX00000) #
echo "# Update (0bX00000) #"
readonly targetAction="action${targetAB}.sh"
readonly actionUrl="https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/src/${targetAction}"
readonly actionDigestUrl="https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/src/${targetAction}.sha512"

shellDigest="$(curl -sSfL -m ${curlTimeout} "${actionDigestUrl}")"
if [[ $? -eq ${EXIT_SUCCESS} && -n "${shellDigest}" ]];
then
	echo "Successfully fetched the SHA-512 value of the latest \`\`${targetAction}\`\` from GitHub. "
	if [[ -f "${targetAction}" && "$(sha512sum "${targetAction}" | cut -d " " -f1)" == "${shellDigest}" ]];
	then
		echo "The target action \`\`${targetAction}\`\` is already up-to-date. "
		if [[ -f "${actionPropFilePath}" && "$(cat "${actionPropFilePath}")" == "${currentAB}" ]];
		then
			echo "The action slot remained ${currentAB}. "
		else
			echo "The action slot seemed inconsistent with the actual one. "
			rm -f "${actionPropFilePath}" && echo -n "${currentAB}" > "${actionPropFilePath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -f "${actionPropFilePath}" ]];
			then
				echo "Successfully synchronized the actual action slot to \"${actionPropFilePath}\". "
			else
				exitCode=$((exitCode | 32))
				echo "Failed to synchronize the actual action slot to \"${actionPropFilePath}\". "
			fi
		fi
	else
		echo "The target action \`\`${targetAction}\`\` is out-of-date and needs to be updated. "
		shellContent="$(curl -sSfL -m ${curlTimeout} "${actionUrl}")"
		if [[ $? -eq ${EXIT_SUCCESS} && -n "${shellContent}" ]];
		then
			echo "Successfully fetched the latest \`\`${targetAction}\`\` from GitHub. "
			if [[ "$(echo "${shellContent}" | sha512sum | cut -d " " -f1)" == "${shellDigest}" ]];
			then
				echo "Successfully verified the latest \`\`${targetAction}\`\`. "
				if echo "${shellContent}" | sh -n;
				then
					echo "The latest \`\`${targetAction}\`\` successfully passed the local shell syntax check (sh). "
					rm -f "${targetAction}"
					echo "${shellContent}" > "${targetAction}"
					if [[ $? -eq ${EXIT_SUCCESS} && -f "${targetAction}" ]];
					then
						echo "Successfully updated \`\`${targetAction}\`\`. "
						rm -f "${actionPropFilePath}" && echo -n "${targetAB}" > "${actionPropFilePath}"
						if [[ $? -eq ${EXIT_SUCCESS} && -f "${actionPropFilePath}" ]];
						then
							echo "Successfully switched the action slot to ${targetAB} in \"${actionPropFilePath}\". "
						else
							exitCode=$((exitCode | 32))
							echo "Failed to switch the action slot to ${targetAB} in \"${actionPropFilePath}\". "
						fi
					else
						exitCode=$((exitCode | 32))
						echo "Failed to update \`\`${targetAction}\`\`. "
					fi
				else
					exitCode=$((exitCode | 32))
					echo "The latest \`\`${targetAction}\`\` failed to pass the local shell syntax check (sh). "
				fi
			else
				exitCode=$((exitCode | 32))
				echo "Failed to verify the latest \`\`${targetAction}\`\`. "
			fi
		else
			exitCode=$((exitCode | 32))
			echo "Failed to fetch the latest \`\`${targetAction}\`\` from GitHub. "
		fi
	fi
else
	exitCode=$((exitCode | 32))
	echo "Failed to fetch the SHA-512 value of the latest \`\`${targetAction}\`\` from GitHub. "
fi
echo ""

# Exit #
readonly endTime=$(date +%s%N)
readonly timeDelta=$((endTime - startTime - gapTime))
readonly variableFileName="variables.log"
readonly variableFilePath="${generationOutputDirectoryPath}/${variableFileName}"

set > "${variableFilePath}"
if [[ ${EXIT_SUCCESS} -eq $((exitCode & EXIT_FAILURE)) ]];
then
	setPermissions && chmod 755 "${actionDirectoryPath}"
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		echo "Successfully set permissions. "
	else
		exitCode=$((exitCode | ${EXIT_FAILURE}))
		echo "Failed to set permissions. "
	fi
fi
clearCaches
if [[ $? -eq ${EXIT_SUCCESS} ]];
then
	echo "Successfully cleared caches. "
else
	exitCode=$((exitCode | ${EXIT_FAILURE}))
	echo "Failed to clear caches. "
fi
echo "Finished executing the \`\`action.sh\`\` in $((timeDelta / 1000000000)).$((timeDelta % 1000000000)) second(s) (${exitCode}). "
exit ${exitCode}
