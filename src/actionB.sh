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
readonly actionFolderPath="$(dirname "$0")"
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
	exitCode=$(expr ${exitCode} \| ${EXIT_FAILURE})
	echo "Failed to clear caches. "
fi
chmod 755 "${actionFolderPath}" && cd "${actionFolderPath}"
if [[ $? -eq ${EXIT_SUCCESS} && "$(basename "$(pwd)")" == "${moduleId}" ]];
then
	echo "The current working directory is \"$(pwd)\". "
	setPermissions
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		echo "Successfully set permissions. "
	else
		exitCode=$(expr ${exitCode} \| ${EXIT_FAILURE})
		echo "Failed to set permissions. "
	fi
else
	echo "The working directory \"$(pwd)\" is unexpected. "
	exitCode=$(expr ${exitCode} \| ${EXIT_FAILURE})
fi
androidVersion=$(getprop ro.build.version.release)
if ${BOOTMODE};
then
	if [[ "${KSU}" == "true" ]];
	then
		echo "KSU (${KSU_VER_CODE}): Please "
		echo "- patch the kernel to support SukiSU-Ultra and SUSFS, "
		echo "- deploy the latest SukiSU-Ultra from the \`\`Actions\`\` tab of its GitHub repository with only applications requiring root privileges configured and granted in the SukiSU-Ultra Manager, "
		echo "- install the latest BRENE SUSFS module as a system module, "
		echo "- install the latest Zygisk Next module as a system module with Denylist Policy set to Unmount Only, "
		echo "- install the latest \`\`Jing Matrix\`\` branch of the LSPosed module from the \`\`Actions\`\` tab of its GitHub repository as a system module with logging disabled and the narrowest scope configured for each plugin, "
		echo "- install the latest Play Integrity Fix (PIF) module as a system module, "
		echo "- install the latest Tricky Store (TS) module as a system module with the correct configurations, "
		echo "- install the latest Audit Patch module as a system module if the BRENE SUSFS module is not working, and"
		if [[ ${androidVersion} -ge 12 ]];
		then
			echo "- activate the latest HMA-OSS plugin with the correct configurations and the latest FuseFixer plugin. "
		else
			echo "- activate the latest HMA-OSS plugin with the correct configurations. "
		fi
		if [[ -d "${apatchFolder}" ]];
		then
			echo "The Apatch folder exists while KSU or one of its variants is using. Please consider removing the Apatch folder. "
		fi
		if [[ -d "${magiskFolder}" ]];
		then
			echo "The Magisk folder exists while KSU or one of its variants is using. Please consider removing the Magisk folder. "
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
			echo "The Magisk folder exists while the Apatch is using. Please consider removing the Magisk folder. "
		fi
		if [[ -d "${ksuFolder}" ]];
		then
			echo "The KSU folder exists while the Apatch is using. Please consider removing the KSU folder. "
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
				echo "The Apatch folder exists while the Magisk is using. Please consider removing the Apatch folder. "
			fi
			if [[ -d "${ksuFolder}" ]];
			then
				echo "The KSU folder exists while the Magisk is using. Please consider removing the KSU folder. "
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
readonly zygiskNextConfigurationFolderPath="${adbFolder}/zygisksu"
readonly zygiskNextDenylistEnforceConfigurationFileName="denylist_enforce"
readonly zygiskNextDenylistEnforceConfigurationFilePath="${zygiskNextConfigurationFolderPath}/${zygiskNextDenylistEnforceConfigurationFileName}"
readonly zygiskNextDenylistPolicyConfigurationFileName="denylist_policy"
readonly zygiskNextDenylistPolicyConfigurationFilePath="${zygiskNextConfigurationFolderPath}/${zygiskNextDenylistPolicyConfigurationFileName}"
readonly shamikoModuleId="zygisk_shamiko"
readonly shamikoConfigurationFolderPath="${adbFolder}/shamiko"
readonly shamikoWhitelistConfigurationFileName="whitelist"
readonly shamikoWhitelistConfigurationFilePath="${shamikoConfigurationFolderPath}/${shamikoWhitelistConfigurationFileName}"
readonly zygiskAssistantModuleId="zygisk-assistant"
readonly noHelloModuleId="zygisk_nohello"
readonly noHelloConfigurationFolderPath="${adbFolder}/nohello"
readonly noHelloWhitelistConfigurationFileName="whitelist"
readonly noHelloWhitelistConfigurationFilePath="${noHelloConfigurationFolderPath}/${noHelloWhitelistConfigurationFileName}"
readonly rezygiskConfigurationFolderPath="${adbFolder}/rezygisk"
readonly neozygiskConfigurationFolderPath="${adbFolder}/neozygisk"
readonly builtInZygiskFilePath="${adbFolder}/magisk/zygisk"

function isModuleInstalled
{
	moduleInstallationFolderPath="${magiskModuleFolder}/$1"
	if [[ -d "${moduleInstallationFolderPath}" ]];
	then
		modulePropFileName="module.prop"
		modulePropFilePath="${moduleInstallationFolderPath}/${modulePropFileName}"
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
			mkdir -p "${shamikoConfigurationFolderPath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -d "${shamikoConfigurationFolderPath}" ]];
			then
				echo "Successfully prepared the Shamiko configuration folder \"${shamikoConfigurationFolderPath}\". "
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
						exitCode=$(expr ${exitCode} \| 2)
						echo "Failed to create the Shamiko whitelist configuration file \"${shamikoWhitelistConfigurationFilePath}\". "
					fi
				fi
			else
				echo "Failed to prepare the Shamiko configuration folder \"${shamikoConfigurationFolderPath}\". "
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
			mkdir -p "${noHelloConfigurationFolderPath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -d "${noHelloConfigurationFolderPath}" ]];
			then
				echo "Successfully prepared the NoHello configuration folder \"${noHelloConfigurationFolderPath}\". "
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
						exitCode=$(expr ${exitCode} \| 2)
						echo "Failed to create the NoHello whitelist configuration file \"${noHelloWhitelistConfigurationFilePath}\". "
					fi
				fi
			else
				echo "Failed to prepare the NoHello configuration folder \"${noHelloConfigurationFolderPath}\". "
			fi
		else
			echo "The NoHello module was not installed. "
		fi
		if [[ "Zygisk Next" == "${zygiskSolutionModuleName}" ]];
		then
			mkdir -p "${zygiskNextConfigurationFolderPath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -d "${zygiskNextConfigurationFolderPath}" ]];
			then
				echo "Successfully prepared the Zygisk Next configuration folder \"${zygiskNextConfigurationFolderPath}\". "
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
						exitCode=$(expr ${exitCode} \| 2)
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
						exitCode=$(expr ${exitCode} \| 2)
						echo "Failed to write \"${toBeWritten}\" to the Zygisk Next denylist enforce configuration file \"${zygiskNextDenylistEnforceConfigurationFilePath}\". "
					fi
				fi
			else
				echo "Failed to prepare the Zygisk Next configuration folder \"${zygiskNextConfigurationFolderPath}\". "
			fi
			if [[ -d "${rezygiskConfigurationFolderPath}" ]];
			then
				echo "The ReZygisk configuration folder exists while the Zygisk Next is using. Please consider removing the ReZygisk configuration folder. "
			fi
			if [[ -d "${neozygiskConfigurationFolderPath}" ]];
			then
				echo "The NeoZygisk configuration folder exists while the Zygisk Next is using. Please consider removing the NeoZygisk configuration folder. "
			fi
		elif [[ "ReZygisk" == "${zygiskSolutionModuleName}" ]];
		then
			if [[ -d "${zygiskNextConfigurationFolderPath}" ]];
			then
				echo "The Zygisk Next configuration folder exists while the ReZygisk is using. Please consider removing the Zygisk Next configuration folder. "
			fi
			if [[ -d "${neozygiskConfigurationFolderPath}" ]];
			then
				echo "The NeoZygisk configuration folder exists while the ReZygisk is using. Please consider removing the NeoZygisk configuration folder. "
			fi
		elif [[ "NeoZygisk" == "${zygiskSolutionModuleName}" ]];
		then
			if [[ -d "${zygiskNextConfigurationFolderPath}" ]];
			then
				echo "The Zygisk Next configuration folder exists while the NeoZygisk is using. Please consider removing the Zygisk Next configuration folder. "
			fi
			if [[ -d "${rezygiskConfigurationFolderPath}" ]];
			then
				echo "The ReZygisk configuration folder exists while the NeoZygisk is using. Please consider removing the ReZygisk configuration folder. "
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
readonly webrootFolderPath="${webrootName}"
readonly webrootFilePath="${webrootName}.zip"
readonly webrootUrl="https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/src/webroot.zip"
readonly webrootDigestUrl="https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/src/webroot.zip.sha512"
readonly curlTimeout=10
readonly actionPropFileName="action.prop"
readonly actionPropFilePath="${webrootFolderPath}/${actionPropFileName}"
readonly dataAppFolder="/data/app"
readonly largerOldScanningScope="/data"
readonly smallerOldScanningScope="/data/misc"
if [[ -n "${EXTERNAL_STORAGE}" ]];
then
	readonly downloadFolderPath="${EXTERNAL_STORAGE}/Download"
else
	readonly downloadFolderPath="/sdcard/Download"
fi
readonly cppBinaryFileName="generate"
readonly cppBinaryFilePath="${webrootFolderPath}/${cppBinaryFileName}_$(getprop ro.product.cpu.abi)"
readonly databaseFileName="database.json"
readonly databaseFilePath="${webrootFolderPath}/${databaseFileName}"
readonly whitelist92ConfigurationFileName=".v92HMAWhitelistModeConfiguration.json"
readonly whitelist92ConfigurationFilePath="${downloadFolderPath}/${whitelistConfigurationFileName}"
readonly blacklist92ConfigurationFileName=".v92HMABlacklistModeConfiguration.json"
readonly blacklist92ConfigurationFilePath="${downloadFolderPath}/${blacklistConfigurationFileName}"
readonly whitelist93ConfigurationFileName=".v93HMAOSSWhitelistModeConfiguration.json"
readonly whitelist93ConfigurationFilePath="${downloadFolderPath}/${whitelistConfigurationFileName}"
readonly blacklist93ConfigurationFileName=".v93HMAOSSBlacklistModeConfiguration.json"
readonly blacklist93ConfigurationFilePath="${downloadFolderPath}/${blacklistConfigurationFileName}"
readonly pathTesterFileName=".pathTester.sh"
readonly pathTesterFilePath="${downloadFolderPath}/${pathTesterFileName}"
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

webrootDigest="$(curl -s -m ${curlTimeout} "${webrootDigestUrl}")"
if [[ $? -eq ${EXIT_SUCCESS} && -n "${webrootDigest}" ]];
then
	echo "Successfully fetched the SHA-512 value of the latest ZIP file of the web UI. "
	if [[ -d "${webrootFolderPath}" && "$(find "${webrootFolderPath}" -type f ! -name "*.sha512" ! -name "*.prop" -exec sha512sum {} \; | sort)" == "${webrootDigest}" ]];
	then
		echo "The current web UI is already up-to-date. "
	else
		echo "The current web UI is out-of-date and needs to be updated. "
		abortFlag=${EXIT_SUCCESS}
		if [[ -d "${webrootFolderPath}" ]];
		then
			rm -rf "${webrootFolderPath}.bak" && mv -fT "${webrootFolderPath}" "${webrootFolderPath}.bak"
			if [[ $? -eq ${EXIT_SUCCESS} && -d "${webrootFolderPath}.bak" ]];
			then
				echo "Successfully moved \"${webrootFolderPath}\" to \"${webrootFolderPath}.bak\". "
			else
				abortFlag=${EXIT_FAILURE}
				exitCode=$(expr ${exitCode} \| 32)
				echo "Failed to move \"${webrootFolderPath}\" to \"${webrootFolderPath}.bak\". "
			fi
		else
			echo "No old web UI folders were found to be backed up. "
		fi
		if [[ ${EXIT_SUCCESS} -eq ${abortFlag} ]];
		then
			curl -s -m ${curlTimeout} "${webrootUrl}" -o "${webrootFilePath}" && unzip "${webrootFilePath}" -d "${webrootFolderPath}" && rm -f "${webrootFilePath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -d "${webrootFolderPath}" && "$(find "${webrootFolderPath}" -type f ! -name "*.sha512" ! -name "*.prop" -exec sha512sum {} \; | sort)" == "${webrootDigest}" ]];
			then
				echo "Successfully updated and verified the web UI. "
				if [[ -d "${webrootFolderPath}.bak" ]];
				then
					cp -fp "${webrootFolderPath}.bak/${actionPropFileName}" "${actionPropFilePath}"
					if [[ $? -eq ${EXIT_SUCCESS} && ! -e "${webrootFolderPath}.bak" ]];
					then
						echo "Successfully restored the action slot. "
						rm -rf "${webrootFolderPath}.bak"
						if [[ $? -eq ${EXIT_SUCCESS} && ! -e "${webrootFolderPath}.bak" ]];
						then
							echo "Successfully removed \"${webrootFolderPath}.bak\". "
						else
							echo "Failed to remove \"${webrootFolderPath}.bak\". "
						fi
					else
						echo "Failed to restore the action slot. "
					fi
				else
					echo "No old web UI folders that should be removed were found. "
				fi
			else
				exitCode=$(expr ${exitCode} \| 32)
				echo "Failed to update or verify the web UI. "
				if [[ -d "${webrootFolderPath}.bak" ]];
				then
					rm -rf "${webrootFolderPath}" && mv -fT "${webrootFolderPath}.bak" "${webrootFolderPath}"
					if [[ $? -eq ${EXIT_SUCCESS} && -d "${webrootFolderPath}" ]];
					then
						echo "Successfully restored \"${webrootFolderPath}.bak\" to \"${webrootFolderPath}\". "
					else
						echo "Failed to restore \"${webrootFolderPath}.bak\" to \"${webrootFolderPath}\". "
					fi
				else
					echo "No old web UI folders were found for restoring. "
				fi
			fi
		fi
	fi
else
	exitCode=$(expr ${exitCode} \| 32)
	echo "Failed to fetch the SHA-512 value of the latest ZIP file of the web UI. "
fi
if [[ $(expr ${exitCode} \& 32) -ne ${EXIT_SUCCESS} ]];
then
	echo "The updating of the \`\`${databaseFileName}\`\` might fail. This will use the cache to generate the configurations for HMA and its variants. "
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
	gapTime=$(expr ${endGapTime} - ${startGapTime})
fi
if [[ ${VK_UP} -eq ${keyCode} || ${VK_DOWN} -eq ${keyCode} ]];
then
	folderCount=0
	fileCount=0
	failureInstallationCount=0
	failureInstallationRemovedCount=0
	for item in "${dataAppFolder}/"*
	do
		if [[ -d "${item}" ]];
		then
			if basename "${item}" | grep -qE "^vmdl[0-9]+\\.tmp\$";
			then
				failureInstallationCount=$(expr ${failureInstallationCount} + 1)
				if rm -rf "${item}";
				then
					failureInstallationRemovedCount=$(expr ${failureInstallationRemovedCount} + 1)
					echo "[${failureInstallationRemovedCount}/${failureInstallationCount}] Found a failure installation at \"${item}\", which has been removed. "
				else
					echo "[${failureInstallationRemovedCount}/${failureInstallationCount}] Found a failure installation at \"${item}\", which could not be removed. "
				fi
			else
				folderCount=$(expr ${folderCount} + 1)
				subItems="$(ls -1 "${item}")"
				if [[ $(echo "${subItems}" | wc -l) -ne 1 ]];
				then
					echo "- There is at least 1 additional item in \"${item}\", which should not exist. "
				fi
			fi
		elif [ -f "${item}" ];
		then
			if [[ "${item}" == *.apk ]];
			then
				fileCount=$(expr ${fileCount} + 1)
			else
				echo "- A file that should not exist was found at \"${item}\". "
			fi
		fi
	done
	if [[ ${folderCount} -gt 0 ]] && [[ ${fileCount} -gt 0 ]];
	then
		echo "A mixture of folders and files was detected in the \"${dataAppFolder}\" directory. "
	fi
	if [[ ${failureInstallationCount} -ge 1 ]];
	then
		echo "Found ${failureInstallationCount} failure installation(s) in the \"${dataAppFolder}\" directory with ${failureInstallationRemovedCount} removed successfully. "
	fi
	oldConfigurationFolderCount=0
	removedOldConfigurationFolderCount=0
	echo "Removing old configuration directories of HMA and its variants. "
	for oldPath in $(find "${largerOldScanningScope}" -type d -and \( -name "*h_m_a_l*" -or -name "*hma*" -or -name "*hma1*" -or -name "hmal*" \))
	do
		if [[ -e "${oldPath}/config.json" && -d "${oldPath}/log" ]];
		then
			oldConfigurationFolderCount=$(expr ${oldConfigurationFolderCount} + 1)
			if rm -rf "${oldPath}";
			then
				removedOldConfigurationFolderCount=$(expr ${removedOldConfigurationFolderCount} + 1)
				echo "[${removedOldConfigurationFolderCount}/${oldConfigurationFolderCount}] Successfully removed \"${oldPath}\" (L). "
			else
				echo "[${removedOldConfigurationFolderCount}/${oldConfigurationFolderCount}] Failed to remove \"${oldPath}\" (L). "
			fi
		fi
	done
	for oldPath in $(find "${smallerOldScanningScope}" -mindepth 2 -type d -and \( -name "*h_m_a_l*" -or -name "*hma*" -or -name "*hma1*" -or -name "hmal*" \))
	do
		if [[ -z "$(ls -A "${oldPath}")" ]];
		then
			oldConfigurationFolderCount=$(expr ${oldConfigurationFolderCount} + 1)
			if rm -rf "${oldPath}";
			then
				removedOldConfigurationFolderCount=$(expr ${removedOldConfigurationFolderCount} + 1)
				echo "[${removedOldConfigurationFolderCount}/${oldConfigurationFolderCount}] Successfully removed \"${oldPath}\" (S). "
			else
				echo "[${removedOldConfigurationFolderCount}/${oldConfigurationFolderCount}] Failed to remove \"${oldPath}\" (S). "
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
mkdir -p "${downloadFolderPath}"
if [[ $? -eq ${EXIT_SUCCESS} && -d "${downloadFolderPath}" ]];
then
	echo "Successfully prepared the folder \"${downloadFolderPath}\". "
	chmod u+x "${cppBinaryFilePath}"
	"${cppBinaryFilePath}" -i "${databaseFilePath}" -ow92 "${whitelist92ConfigurationFilePath}" -ob92 "${blacklist92ConfigurationFilePath}" -ow93 "${whitelist93ConfigurationFilePath}" -ob93 "${blacklist93ConfigurationFilePath}" -op "${pathTesterFilePath}"
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		if [[ -f "${whitelist92ConfigurationFilePath}" ]];
		then
			echo "Successfully generated the configuration file \"${whitelist92ConfigurationFilePath}\". "
		else
			exitCode=$(expr ${exitCode} \| 4)
			echo "Failed to generate the configuration file \"${whitelist92ConfigurationFilePath}\". "
		fi
		if [[ -f "${blacklist92ConfigurationFilePath}" ]];
		then
			echo "Successfully generated the configuration file \"${blacklist92ConfigurationFilePath}\". "
		else
			exitCode=$(expr ${exitCode} \| 4)
			echo "Failed to generate the configuration file \"${blacklist92ConfigurationFilePath}\". "
		fi
		if [[ -f "${whitelist93ConfigurationFilePath}" ]];
		then
			echo "Successfully generated the configuration file \"${whitelist93ConfigurationFilePath}\". "
		else
			exitCode=$(expr ${exitCode} \| 4)
			echo "Failed to generate the configuration file \"${whitelist93ConfigurationFilePath}\". "
		fi
		if [[ -f "${blacklist93ConfigurationFilePath}" ]];
		then
			echo "Successfully generated the configuration file \"${blacklist93ConfigurationFilePath}\". "
		else
			exitCode=$(expr ${exitCode} \| 4)
			echo "Failed to generate the configuration file \"${blacklist93ConfigurationFilePath}\". "
		fi
		if [[ -f "${pathTesterFilePath}" ]];
		then
			echo "Successfully generated the path tester file \"${pathTesterFilePath}\". "
		else
			exitCode=$(expr ${exitCode} \| 4)
			echo "Failed to generate the path tester file \"${pathTesterFilePath}\". "
		fi
	else
		exitCode=$(expr ${exitCode} \| 4)
		echo "Failed to generate relevant files for HMA and its variants. "
	fi
	chmod -x "${cppBinaryFilePath}"
else
	exitCode=$(expr ${exitCode} \| 4)
	echo "Failed to prepare the folder \"${downloadFolderPath}\". "
fi
echo ""

# Tricky Store (0b00X000) #
echo "# Tricky Store (0b00X000) #"
readonly trickyStoreConfigurationFolderPath="${adbFolder}/tricky_store"
readonly trickyStoreSecurityPatchFileName="security_patch.txt"
readonly trickyStoreSecurityPatchFilePath="${trickyStoreConfigurationFolderPath}/${trickyStoreSecurityPatchFileName}"
readonly trickyStoreTargetExclusionFileName="trickyStoreTargetExclusions.txt"
readonly trickyStoreTargetExclusionFilePath="${classificationFolderPath}/${trickyStoreTargetExclusionFileName}"
readonly trickyStoreTargetFileName="target.txt"
readonly trickyStoreTargetFilePath="${trickyStoreConfigurationFolderPath}/${trickyStoreTargetFileName}"

if [[ -d "${trickyStoreConfigurationFolderPath}" ]];
then
	echo "The Tricky Store configuration folder was found at \"${trickyStoreConfigurationFolderPath}\". "
	if [[ -f "${trickyStoreSecurityPatchFilePath}" ]];
	then
		echo "The security patch file was found at \"${trickyStoreSecurityPatchFilePath}\". "
		if mv -f "${trickyStoreSecurityPatchFilePath}" "${trickyStoreSecurityPatchFilePath}.bak";
		then
			echo "Successfully removed \"${trickyStoreSecurityPatchFilePath}\" by renaming to \`\`${trickyStoreSecurityPatchFileName}.bak\`\`. "
		else
			exitCode=$(expr ${exitCode} \| 8)
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
		echo "The backing up has been skipped since the Tricky Store target file \"${trickyStoreTargetFilePath}\" did not exist. "
	fi
	if [[ ${EXIT_SUCCESS} -eq ${abortFlag} ]];
	then
		chmod u+x "${cppBinaryFilePath}"
		"${cppBinaryFilePath}" -i "${databaseFilePath}" -ot "${trickyStoreTargetFilePath}"
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
	echo "The Tricky Store configuration folder did not exist. "
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
readonly directoryForTesting="/data/data/com.android.settings"
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
		sensitiveApplicationCount=$(expr ${sensitiveApplicationCount} + 1)
		if pm disable "${sensitiveApplication}" &> /dev/null;
		then
			disabledSensitiveApplicationCount=$(expr ${disabledSensitiveApplicationCount} + 1)
			echo "- The sensitive application \"${sensitiveApplication}\" was detected, which has been disabled. "
		else
			exitCode=$(expr ${exitCode} \| 16)
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
		exitCode=$(expr ${exitCode} \| 16)
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
			exitCode=$(expr ${exitCode} \| 16)
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
		exitCode=$(expr ${exitCode} \| 16)
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
		exitCode=$(expr ${exitCode} \| 16)
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
		targetXmlFolderPath="$(dirname "${targetXmlFilePath}")"
		if mkdir -p "${targetXmlFolderPath}";
		then
			echo "Successfully created the folder \"${targetXmlFolderPath}\". "
			toBeWritten=$(sed -E 's/(enableAfterTargetSdk=")[0-9]+(" id="143937733")/\10\2/g' "${sourceXmlFilePath}")
			echo -n "${toBeWritten}" > "${targetXmlFilePath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -f "${targetXmlFilePath}" ]];
			then
				echo "Successfully generated \"${targetXmlFilePath}\". "
			else
				exitCode=$(expr ${exitCode} \| 16)
				echo "Failed to generate \"${targetXmlFilePath}\". "
			fi
		else
			exitCode=$(expr ${exitCode} \| 16)
			echo "Failed to create the folder \"${targetXmlFolderPath}\". "
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
readonly currentAB="B"
readonly targetAB="A"
readonly targetAction="action${targetAB}.sh"
readonly actionUrl="https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/src/${targetAction}"
readonly actionDigestUrl="https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/src/${targetAction}.sha512"

shellDigest="$(curl -s -m ${curlTimeout} "${actionDigestUrl}")"
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
				exitCode=$(expr ${exitCode} \| 32)
				echo "Failed to synchronize the actual action slot to \"${actionPropFilePath}\". "
			fi
		fi
	else
		echo "The target action \`\`${targetAction}\`\` is out-of-date and needs to be updated. "
		shellContent="$(curl -s "${actionUrl}")"
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
							exitCode=$(expr ${exitCode} \| 32)
							echo "Failed to switch the action slot to ${targetAB} in \"${actionPropFilePath}\". "
						fi
					else
						exitCode=$(expr ${exitCode} \| 32)
						echo "Failed to update \`\`${targetAction}\`\`. "
					fi
				else
					exitCode=$(expr ${exitCode} \| 32)
					echo "The latest \`\`${targetAction}\`\` failed to pass the local shell syntax check (sh). "
				fi
			else
				exitCode=$(expr ${exitCode} \| 32)
				echo "Failed to verify the latest \`\`${targetAction}\`\`. "
			fi
		else
			exitCode=$(expr ${exitCode} \| 32)
			echo "Failed to fetch the latest \`\`${targetAction}\`\` from GitHub. "
		fi
	fi
else
	exitCode=$(expr ${exitCode} \| 32)
	echo "Failed to fetch the SHA-512 value of the latest \`\`${targetAction}\`\` from GitHub. "
fi
echo ""

# Exit #
readonly endTime=$(date +%s%N)
readonly timeDelta=$(expr ${endTime} - ${startTime} - ${gapTime})

if [[ ${EXIT_SUCCESS} -eq $(expr ${exitCode} \& ${EXIT_FAILURE}) ]];
then
	setPermissions && chmod 755 "${actionFolderPath}"
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		echo "Successfully set permissions. "
	else
		exitCode=$(expr ${exitCode} \| ${EXIT_FAILURE})
		echo "Failed to set permissions. "
	fi
fi
clearCaches
if [[ $? -eq ${EXIT_SUCCESS} ]];
then
	echo "Successfully cleared caches. "
else
	exitCode=$(expr ${exitCode} \| ${EXIT_FAILURE})
	echo "Failed to clear caches. "
fi
echo "Finished executing the \`\`action.sh\`\` in $(expr ${timeDelta} / 1000000000).$(expr ${timeDelta} % 1000000000) second(s) (${exitCode}). "
exit ${exitCode}
