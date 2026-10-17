#!/usr/bin/env bash
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EOF=255
readonly CPP_SOURCE_DIRECTORY_PATH="."
readonly CPP_BINARY_DIRECTORY_PATH="bin"
readonly ARCHITECTURE_COMPILER_MAPPINGS=(
	"arm64-v8a:aarch64-linux-android21-clang++"
	"armeabi-v7a:armv7a-linux-androideabi21-clang++"
	"x86_64:x86_64-linux-android21-clang++"
	"x86:i686-linux-android21-clang++"
)
readonly DEFAULT_FILE_MODE=644

# Collect all the "*.cpp" source files except "generate.cpp" #
shopt -s nullglob
cppSourceFilePaths=()
for cppSourceFilePath in "${CPP_SOURCE_DIRECTORY_PATH}"/*.cpp;
do
	if [[ "$(basename -- "${cppSourceFilePath}")" != "generate.cpp" ]];
	then
		cppSourceFilePaths+=( "${cppSourceFilePath}" )
	fi
done
shopt -u nullglob
if [[ ${#cppSourceFilePaths[@]} -eq 0 ]];
then
	printf 'No CPP source files were collected under "%q". \n' "${CPP_SOURCE_DIRECTORY_PATH}" >&2
	exit ${EOF}
fi

# Prepare output directory #
if mkdir -p -- "${CPP_BINARY_DIRECTORY_PATH}";
then
	printf 'Successfully prepared the directory "%q". \n' "${CPP_BINARY_DIRECTORY_PATH}" >&2
else
	printf 'Failed to prepare the directory "%q". \n' "${CPP_BINARY_DIRECTORY_PATH}" >&2
	exit ${EOF}
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
		returnCode=$?
		if [[ ${EXIT_SUCCESS} -eq ${returnCode} && -z "${compilationOutputs}" && -f "${cppBinaryFilePath}" ]];
		then
			if chmod "${DEFAULT_FILE_MODE}" -- "${cppBinaryFilePath}" >/dev/null 2>&1;
			then
				printf 'Successfully compiled "%q" to "%q". \n' "${cppSourceFilePath}" "${cppBinaryFilePath}" >&2
			else
				printf 'Compiled "%q" to "%q" without permissions set to %s. \n' "${cppSourceFilePath}" "${cppBinaryFilePath}" "${DEFAULT_FILE_MODE}" >&2
			fi
		else
			exitStatus=${EXIT_FAILURE}
			if [[ -n "${compilationOutputs}" ]];
			then
				printf 'Failed to compile "%q" to "%q", or warnings occurred during the compilation due to "%q". \n' "${cppSourceFilePath}" "${cppBinaryFilePath}" "${compilationOutputs}" >&2
			else
				printf 'Failed to compile "%q" to "%q", or warnings occurred during the compilation. \n' "${cppSourceFilePath}" "${cppBinaryFilePath}" >&2
			fi
		fi
	done
done

exit ${exitStatus}
