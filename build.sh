#!/bin/bash
# Module (11--12) #
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EOF=255
readonly moduleName="Bypasser"
readonly moduleId="bypasser"
readonly moduleVersion="$(date +%Y%m%d%H)"
readonly moduleFolderPath="$(dirname "$0")"

function setPermissions
{
	returnCode=${EXIT_SUCCESS}
	if [[ -n "$(find . -type d -exec chmod 755 {} \; 2>&1)" ]];
	then
		returnCode=${EXIT_FAILURE}
	fi
	if [[ -n "$(find . -type f ! -name "*.sha512" ! -name "LICENSE" ! -name "build.sh" -exec chmod 644 {} \; 2>&1)" ]];
	then
		returnCode=${EXIT_FAILURE}
	fi
	if [[ -n "$(find . -type f -name "*.sha512" -exec chmod 444 {} \; 2>&1)" ]];
	then
		returnCode=${EXIT_FAILURE}
	fi
	chmod 444 "LICENSE"
	if [[ $? -ne ${EXIT_SUCCESS} ]];
	then
		returnCode=${EXIT_FAILURE}
	fi
	chmod 744 "build.sh"
	if [[ $? -ne ${EXIT_SUCCESS} ]];
	then
		returnCode=${EXIT_FAILURE}
	fi
	return ${returnCode}
}

echo "Welcome to the builder for the ${moduleName} rooting-layer system module! "
echo "The absolute path to this script is \"$(cd "$(dirname "$0")" && pwd)/$(basename "$0")\". "
chmod 755 "${moduleFolderPath}" && cd "${moduleFolderPath}"
if [[ $? == ${EXIT_SUCCESS} && "$(basename "$(pwd)")" == "${moduleName}" ]];
then
	echo "The current working directory is \"$(pwd)\". "
else
	echo "The working directory \"$(pwd)\" is unexpected. "
	exit 11
fi
setPermissions
if [[ $? == ${EXIT_SUCCESS} ]];
then
	echo "Successfully set permissions. "
else
	echo "Failed to set permissions. "
	exit 12
fi

# Check (13--15) #
readonly currentPattern="readonly currentAB="
readonly targetPattern="readonly targetAB="
readonly srcFolderPath="src"
readonly shellAFileName="actionA.sh"
readonly shellAFilePath="${srcFolderPath}/${shellAFileName}"
readonly shellBFileName="actionB.sh"
readonly shellBFilePath="${srcFolderPath}/${shellBFileName}"

if [[ -z "$(find . -name "*.sh" -exec bash -n {} \; 2>&1)" ]];
then
	echo "All the scripts successfully passed the local shell syntax check (bash). "
else
	echo "Some of the scripts failed to pass the local shell syntax check (bash). "
	exit 13
fi
if [[
	"$(grep -F "${currentPattern}" "${shellAFilePath}" | head -n 1)" == "${currentPattern}\"A\""
	&& "$(grep -F "${targetPattern}" "${shellAFilePath}" | head -n 1)" == "${targetPattern}\"B\""
	&& "$(grep -F "${currentPattern}" "${shellBFilePath}" | head -n 1)" == "${currentPattern}\"B\""
	&& "$(grep -F "${targetPattern}" "${shellBFilePath}" | head -n 1)" == "${targetPattern}\"A\""
]];
then
	echo "Successfully verified the A/B architecture in \"${shellAFilePath}\" and \"${shellBFilePath}\". "
else
	echo "Failed to verify the A/B architecture in \"${shellAFilePath}\" and \"${shellBFilePath}\". "
	exit 14
fi
if diff <(sed "0,/${currentPattern}/{//d;}; 0,/${targetPattern}/{//d;}" "${shellAFilePath}") \
	<(sed "0,/${currentPattern}/{//d;}; 0,/${targetPattern}/{//d;}" "${shellBFilePath}") > /dev/null;
then
	echo "Successfully verified the differences between \"${shellAFilePath}\" and \"${shellBFilePath}\". "
else
	echo "Failed to verify the differences between \"${shellAFilePath}\" and \"${shellBFilePath}\". "
	exit 15
fi

# Compile (16) #
readonly webrootName="webroot"
readonly webrootFolderPath="${srcFolderPath}/${webrootName}"
timeout=10
readonly cppSourceFolderPath="cpp"
readonly cppSourceFileName="generate.cpp"
readonly cppSourceFilePath="${cppSourceFolderPath}/${cppSourceFileName}"
readonly cppBinaryFileName="generate"

tripleABI=(
	"aarch64-linux-android21, arm64-v8a"
	"armv7a-linux-androideabi21, armeabi-v7a"
	"x86_64-linux-android21, x86_64"
	"i686-linux-android21, x86"
)
compilationFlag=${EXIT_SUCCESS}
for i in "${!tripleABI[@]}";
do
	entryABI="${tripleABI[$i]}"
	keyABI="${entryABI%,*}"
	valueABI="${entryABI#*, }"
	cppBinaryFilePath="${webrootFolderPath}/${cppBinaryFileName}_${valueABI}"
	tripleABI[${i}]="${entryABI}, ${cppBinaryFilePath}"
	if [[ ! -f "${cppBinaryFilePath}" ]];
	then
		compilationFlag=${EXIT_FAILURE}
	fi
done
if [[ ${EXIT_SUCCESS} -eq ${compilationFlag} ]];
then
	read -t ${timeout} -p "CPP executable binaries existing, would you like to compile the CPP sources again [yN]? " choice
	if [[ $? -ne ${EXIT_SUCCESS} ]];
	then
		choice="N"
		echo ""
	fi
	case "${choice^^}" in
		Y|YES|1|T|TRUE)
			choiceFlag=${EXIT_SUCCESS}
			;;
		*)
			choiceFlag=${EXIT_FAILURE}
			;;
	esac
else
	choiceFlag=${EXIT_SUCCESS}
fi
if [[ ${EXIT_SUCCESS} -eq ${choiceFlag} ]];
then
	compilationFlag=${EXIT_SUCCESS}
	for entryABI in "${tripleABI[@]}";
	do
		keyABI="$(echo "${entryABI}" | awk -F ', ' '{print $1}')"
		valueABI="$(echo "${entryABI}" | awk -F ', ' '{print $2}')"
		cppBinaryFilePath="$(echo "${entryABI}" | awk -F ', ' '{print $3}')"
		compilationOutputs="$(${keyABI}-clang++ -O3 -Wall -Wextra -Wpedantic -I "${cppSourceFolderPath}" "${cppSourceFilePath}" -o "${cppBinaryFilePath}" -static-libstdc++ -fPIE -pie 2>&1)"
		returnCode=$?
		if [[ ${EXIT_SUCCESS} == ${returnCode} && -z "${compilationOutputs}" && -f "${cppBinaryFilePath}" ]];
		then
			echo "Successfully compiled \"${cppSourceFilePath}\" to \"${cppBinaryFilePath}\". "
		else
			compilationFlag=${EXIT_FAILURE}
			if [[ -n "${compilationOutputs}" ]];
			then
				echo "Failed to compile \"${cppSourceFilePath}\" to \"${cppBinaryFilePath}\", or warnings occurred during the compilation. Details are as follows. "
				echo "${compilationOutputs}"
			else
				echo "Failed to compile \"${cppSourceFilePath}\" to \"${cppBinaryFilePath}\", or warnings occurred during the compilation. "
			fi
		fi
	done
	if [[ ${EXIT_SUCCESS} -ne ${compilationFlag} ]];
	then
		exit 16
	fi
fi

# Pack (21--27) #
readonly webrootFilePath="${srcFolderPath}/${webrootName}.zip"
readonly propFileName="module.prop"
readonly propFilePath="${srcFolderPath}/${propFileName}"
readonly propContent="id=${moduleId}\n\
name=${moduleName}\n\
version=v${moduleVersion}\n\
versionCode=${moduleVersion}\n\
author=LRFP Team\n\
description=This is a developing rooting-layer system module for systematically bypassing environment detection related to LRFP for Android devices, where the abbreviation \"LRFP\" stands for Low-level, Rooting, Frameworks, and Plugins. \n\
updateJson=https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/update.json"
readonly zipFolderPath="Release"
readonly zipFileName="${moduleName}_v${moduleVersion}.zip"
readonly zipFilePath="${zipFolderPath}/${zipFileName}"

if [[ -d "${srcFolderPath}" && -d "${srcFolderPath}/META-INF" && -d "${srcFolderPath}/system" ]];
then
	echo "Sources were found to be packed. "
	if [[ -d "${webrootFolderPath}" ]];
	then
		echo "The web UI folder was found to be packed. "
		(cd "${webrootFolderPath}" && find . -type f ! -name "*.sha512" ! -name "*.prop" | zip -J -r -v -@ -) > "${webrootFilePath}"
		if [[ $? -eq ${EXIT_SUCCESS} && -f "${webrootFilePath}" ]];
		then
			echo "Successfully packed the web UI folder. "
		else
			echo "Failed to pack the web UI folder. "
			exit 21
		fi
	fi
	echo -e "${propContent}" > "${propFilePath}"
	if [[ $? -eq ${EXIT_SUCCESS} && -f "${propFilePath}" ]];
	then
		echo "Successfully generated the property file \"${propFilePath}\". "
		if [[ -z "$(find "${srcFolderPath}" -type f -name "*.sha512" -delete 2>&1)" ]]
		then
			echo "Successfully removed all the previous SHA-512 value files. "
		else
			echo "Failed to remove all the previous SHA-512 value files. "
			exit 22
		fi
		sha512SuccessCount=0
		sha512TotalCount=0
		for file in $(find "${srcFolderPath}" -type f);
		do
			sha512TotalCount=$(expr ${sha512TotalCount} + 1)
			if [[ "${webrootFilePath}" == "${file}" ]];
			then
				(cd ${srcFolderPath} && find "${webrootName}" -type f ! -name "*.sha512" ! -name "*.prop" -exec sha512sum {} \; | sort) > "${webrootFilePath}.sha512"
				sha512ExitCode=$?
				if [[ ${sha512TotalCount} -ge 1 && ${sha512TotalCount} -le 9 ]];
				then
					echo -n "[0${sha512TotalCount}*] "
				else
					echo -n "[${sha512TotalCount}*] "
				fi
			else
				echo -n "$(sha512sum "${file}" | cut -d " " -f1)" > "${file}.sha512"
				sha512ExitCode=$?
				if [[ ${sha512TotalCount} -ge 1 && ${sha512TotalCount} -le 9 ]];
				then
					echo -n "[0${sha512TotalCount} ] "
				else
					echo -n "[${sha512TotalCount} ] "
				fi
			fi
			if [[ ${EXIT_SUCCESS} -eq ${sha512ExitCode} && -f "${file}.sha512" ]];
			then
				sha512SuccessCount=$(expr ${sha512SuccessCount} + 1)
				echo "Successfully generated the SHA-512 value file of \"${file}\". "
			else
				echo "Failed to generate the SHA-512 value file of \"${file}\". "
			fi
		done
		echo "Successfully generated ${sha512SuccessCount} / ${sha512TotalCount} sha512 file(s). "
		if [[ ${sha512SuccessCount} -ne ${sha512TotalCount} ]];
		then
			exit 23
		fi
		if [[ ! -d "${zipFolderPath}" ]];
		then
			mkdir -p "${zipFolderPath}"
		fi
		if [[ -d "${zipFolderPath}" ]];
		then
			echo "Successfully prepared the ZIP folder path \"${zipFolderPath}\". "
			(cd "${srcFolderPath}" && zip -J -r -v - * -x "${webrootName}.zip" -x "${webrootName}.zip.sha512") > "${zipFilePath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -f "${zipFilePath}" ]];
			then
				echo "Successfully packed the ${moduleName} rooting-layer system module to \"${zipFilePath}\" via the ``zip`` command! "
			else
				echo "Failed to pack the ${moduleName} rooting-layer system module to \"${zipFilePath}\" via the ``zip`` command. "
				exit 24
			fi
		else
			echo "Failed to prepare the ZIP folder path \"${zipFolderPath}\". "
			exit 25
		fi
	else
		echo "Failed to generate the property file \"${propFilePath}\". "
		exit 26
	fi
else
	echo "No sources were found to be packed. "
	exit 27
fi

# Changelog (31--33) #
readonly changelogFolderPath="."
readonly changelogFileName="changelog.md"
readonly changelogFilePath="${changelogFolderPath}/${changelogFileName}"

if [[ $# -ge 1 ]];
then
	history="$(cat "${changelogFilePath}" 2>&1)"
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		echo "Successfully read the changelog \"${changelogFilePath}\". "
	else
		history=""
		echo "Failed to read the changelog \"${changelogFilePath}\". "
	fi
	mkdir -p "${changelogFolderPath}"
	if [[ $? -eq ${EXIT_SUCCESS} && -d "${changelogFolderPath}" ]];
	then
		echo "Successfully prepared the changelog folder path \"${changelogFolderPath}\". "
		echo -e "## ${moduleName}_v${moduleVersion}\n" > "${changelogFilePath}"
		if [[ $? -eq ${EXIT_SUCCESS} && -f "${changelogFilePath}" ]];
		then
			echo "Successfully created the changelog \"${changelogFilePath}\". "
			for argument in "${@}"
			do
				echo "${argument}" >> "${changelogFilePath}"
			done
			echo >> "${changelogFilePath}"
			echo "${history}" >> "${changelogFilePath}"
			if [[ $? -eq ${EXIT_SUCCESS} && -f "${changelogFilePath}" ]];
			then
				echo "Successfully handled the changelog \"${changelogFilePath}\". "
			else
				echo "Failed to handle the changelog \"${changelogFilePath}\". "
				exit 31
			fi
		else
			echo "Failed to create the changelog \"${changelogFilePath}\". "
			exit 32
		fi
	else
		echo "Failed to prepare the changelog folder path \"${changelogFolderPath}\". "
		exit 33
	fi
else
	echo "Finished the dry run of building the ${moduleName} rooting-layer system module. "
	exit ${EXIT_SUCCESS}
fi

# Update (34--36) #
readonly updateFolderPath="."
readonly updateFileName="update.json"
readonly updateFilePath="${updateFolderPath}/${updateFileName}"
readonly updateContent="{\n\
	\"version\":\"v${moduleVersion}\", \n\
	\"versionCode\":${moduleVersion}, \n\
	\"zipUrl\":\"https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/${zipFilePath}\", \n\
	\"changelog\":\"https://raw.githubusercontent.com/LRFP-Team/Bypasser/main/${changelogFileName}\"\n\
}"

mkdir -p "${updateFolderPath}"
if [[ $? -eq ${EXIT_SUCCESS} && -d "${updateFolderPath}" ]];
then
	echo "Successfully prepared the update folder path \"${updateFolderPath}\". "
	echo -e -n "$updateContent" > "${updateFilePath}"
	if [[ $? -eq ${EXIT_SUCCESS} && -f "${updateFilePath}" ]];
	then
		echo "Successfully created the update JSON file \"${updateFilePath}\". "
	else
		echo "Failed to create the update JSON file \"${updateFilePath}\". "
		exit 34
	fi
else
	echo "Failed to prepare the update folder path \"${updateFolderPath}\". "
	exit 35
fi
setPermissions && chmod 755 "${moduleFolderPath}"
if [[ $? == ${EXIT_SUCCESS} ]];
then
	echo "Successfully set permissions. "
else
	echo "Failed to set permissions. "
	exit 36
fi

# Git (37) #
git add . && git commit -m "Module Update (${moduleVersion})" && git push
if [[ $? -eq ${EXIT_SUCCESS} ]];
then
	echo "Successfully pushed to GitHub. "
else
	echo "Failed to push to GitHub. "
	exit 37
fi

# Exit #
exit ${EXIT_SUCCESS}
