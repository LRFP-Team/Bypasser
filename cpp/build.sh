#!/usr/bin/env bash
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EXIT_NOINPUT=66
readonly EXIT_CANTCREAT=73
readonly CPP_SOURCE_DIRECTORY_PATH="."
readonly EXCLUDED_CPP_FILE_NAME="generate.cpp"
readonly CPP_BINARY_DIRECTORY_PATH="bin"
readonly ARCHITECTURE_COMPILER_MAPPINGS=(
	"arm64-v8a:aarch64-linux-android21-clang++"
	"armeabi-v7a:armv7a-linux-androideabi21-clang++"
	"x86_64:x86_64-linux-android21-clang++"
	"x86:i686-linux-android21-clang++"
)
readonly DEFAULT_FILE_MODE=644

# Collect the "*.cpp" source files from the command line or the directory "${CPP_SOURCE_DIRECTORY_PATH}" except "${EXCLUDED_CPP_FILE_NAME}" #
cppSourceFilePaths=()
if [[ $# -gt 0 ]];
then
	for cppSourceFilePath in "$@";
	do
		cppSourceFileName="$(basename -- "${cppSourceFilePath}")"
		if [[ "${cppSourceFileName}" != */* && "${cppSourceFileName}" == *.cpp && "${cppSourceFileName}" != "${EXCLUDED_CPP_FILE_NAME}" && -f "${CPP_SOURCE_DIRECTORY_PATH}/${cppSourceFileName}" ]];
		then
			cppSourceFilePaths+=( "${cppSourceFilePath}" )
		fi
	done
else
	shopt -s nullglob
	for cppSourceFilePath in "${CPP_SOURCE_DIRECTORY_PATH}"/*.cpp;
	do
		if [[ "$(basename -- "${cppSourceFilePath}")" != "${EXCLUDED_CPP_FILE_NAME}" ]];
		then
			cppSourceFilePaths+=( "${cppSourceFilePath}" )
		fi
	done
	shopt -u nullglob
fi
if [[ ${#cppSourceFilePaths[@]} -eq 0 ]];
then
	echo "No CPP source files were collected under ${CPP_SOURCE_DIRECTORY_PATH@Q}. " >&2
	exit ${EXIT_NOINPUT}
fi

# Prepare the output directory #
if mkdir -p -- "${CPP_BINARY_DIRECTORY_PATH}";
then
	echo "Successfully prepared the output directory ${CPP_BINARY_DIRECTORY_PATH@Q}. " >&2
else
	echo "Failed to prepare the output directory ${CPP_BINARY_DIRECTORY_PATH@Q}. " >&2
	exit ${EXIT_CANTCREAT}
fi

# Iterate over each CPP source file and each ABI for compilation #
exitStatus=${EXIT_SUCCESS}
for cppSourceFilePath in "${cppSourceFilePaths[@]}";
do
	cppBinaryFileName="$(basename -- "${cppSourceFilePath}" .cpp)"
	for entryABI in "${ARCHITECTURE_COMPILER_MAPPINGS[@]}";
	do
		architecture="${entryABI%:*}"
		compiler="${entryABI#*:}"
		cppBinaryFilePath="${CPP_BINARY_DIRECTORY_PATH}/${cppBinaryFileName}_${architecture}"
		compilationOutputs="$("${compiler}" -O3 -Wall -Wextra -Wpedantic -I "${CPP_SOURCE_DIRECTORY_PATH}" "${cppSourceFilePath}" -o "${cppBinaryFilePath}" -static-libstdc++ -fPIE -pie 2>&1)"
		returnStatus=$?
		if [[ ${EXIT_SUCCESS} -eq ${returnStatus} && -z "${compilationOutputs}" && -f "${cppBinaryFilePath}" ]];
		then
			if chmod "${DEFAULT_FILE_MODE}" -- "${cppBinaryFilePath}" >/dev/null 2>&1;
			then
				echo "Successfully compiled ${cppSourceFilePath@Q} to ${cppBinaryFilePath@Q}. " >&2
			else
				echo "Compiled ${cppSourceFilePath@Q} to ${cppBinaryFilePath@Q} without permissions set to ${DEFAULT_FILE_MODE}. " >&2
			fi
		else
			exitStatus=${EXIT_FAILURE}
			if [[ -n "${compilationOutputs}" ]];
			then
				echo "Failed to compile ${cppSourceFilePath@Q} to ${cppBinaryFilePath@Q}, or warnings occurred during the compilation due to ${compilationOutputs@Q}. " >&2
			else
				echo "Failed to compile ${cppSourceFilePath@Q} to ${cppBinaryFilePath@Q}, or warnings occurred during the compilation. " >&2
			fi
		fi
	done
done

exit ${exitStatus}
