#!/bin/bash
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EOF=-1
readonly cppBinaryDirectoryPath="bin"
readonly readTimeout=10
readonly cppSourceDirectoryPath="."
readonly cppSourceFileName="analyze.cpp"
readonly cppSourceFilePath="${cppSourceDirectoryPath}/${cppSourceFileName}"
readonly cppBinaryFileName="analyze"

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
	cppBinaryFilePath="${cppBinaryDirectoryPath}/${cppBinaryFileName}_${valueABI}"
	tripleABI[${i}]="${entryABI}, ${cppBinaryFilePath}"
	if [[ ! -f "${cppBinaryFilePath}" ]];
	then
		compilationFlag=${EXIT_FAILURE}
	fi
done
if [[ ${EXIT_SUCCESS} -eq ${compilationFlag} ]];
then
	if [[ -t 0 && -t 1 ]];
	then
		read -t ${readTimeout} -p "CPP executable binaries existing, would you like to compile the CPP sources again [yN]? " choice
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
else
	choiceFlag=${EXIT_SUCCESS}
fi
if [[ ${EXIT_SUCCESS} -eq ${choiceFlag} ]];
then
	mkdir -p "${cppBinaryDirectoryPath}"
	if [[ $? -eq ${EXIT_SUCCESS} ]];
	then
		echo "Successfully prepared the directory \"${cppBinaryDirectoryPath}\". "
		compilationFlag=${EXIT_SUCCESS}
		for entryABI in "${tripleABI[@]}";
		do
			keyABI="$(echo "${entryABI}" | awk -F ', ' '{print $1}')"
			valueABI="$(echo "${entryABI}" | awk -F ', ' '{print $2}')"
			cppBinaryFilePath="$(echo "${entryABI}" | awk -F ', ' '{print $3}')"
			compilationOutputs="$(${keyABI}-clang++ -O3 -Wall -Wextra -Wpedantic -I "${cppSourceDirectoryPath}" "${cppSourceFilePath}" -o "${cppBinaryFilePath}" -static-libstdc++ -fPIE -pie 2>&1)"
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
		exit ${compilationFlag}
	else
		echo "Failed to prepare the directory \"${cppBinaryDirectoryPath}\". "
		exit ${EOF}
	fi
fi