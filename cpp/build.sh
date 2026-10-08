#!/usr/bin/env bash
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EOF=255
readonly cppSourceDirectoryPath="."
readonly cppBinaryDirectoryPath="bin"
readonly tripleABI=(
	"aarch64-linux-android21, arm64-v8a"
	"armv7a-linux-androideabi21, armeabi-v7a"
	"x86_64-linux-android21, x86_64"
	"i686-linux-android21, x86"
)

# Collect all the "*.cpp" source files #
shopt -s nullglob
cppSourceFilePaths=( "${cppSourceDirectoryPath}"/*.cpp )
shopt -u nullglob
if [[ ${#cppSourceFilePaths[@]} -eq 0 ]];
then
	echo "No CPP source files were collected. " >&2
	exit ${EOF}
fi

# Prepare output directory #
mkdir -p "${cppBinaryDirectoryPath}"
if [[ $? -ne ${EXIT_SUCCESS} || ! -d "${cppBinaryDirectoryPath}" ]];
then
	echo "Failed to prepare the directory \"${cppBinaryDirectoryPath}\". " >&2
	exit ${EOF}
fi
echo "Successfully prepared the directory \"${cppBinaryDirectoryPath}\". "

# Iterate over each CPP source file and each ABI for compilation #
compilationFlag=${EXIT_SUCCESS}
for cppSourceFilePath in "${cppSourceFilePaths[@]}";
do
	cppBinaryFileName="$(basename -- "${cppSourceFilePath}" .cpp)"
	for entryABI in "${tripleABI[@]}";
	do
		keyABI="${entryABI%,*}"
		valueABI="${entryABI#*, }"
		cppBinaryFilePath="${cppBinaryDirectoryPath}/${cppBinaryFileName}_${valueABI}"
		compilationOutputs="$(${keyABI}-clang++ -O3 -Wall -Wextra -Wpedantic -I "${cppSourceDirectoryPath}" "${cppSourceFilePath}" -o "${cppBinaryFilePath}" -static-libstdc++ -fPIE -pie 2>&1)"
		returnCode=$?
		if [[ ${EXIT_SUCCESS} -eq ${returnCode} && -z "${compilationOutputs}" && -f "${cppBinaryFilePath}" ]];
		then
			echo "Successfully compiled \"${cppSourceFilePath}\" to \"${cppBinaryFilePath}\". "
		else
			compilationFlag=${EXIT_FAILURE}
			if [[ -n "${compilationOutputs}" ]];
			then
				printf 'Failed to compile "%s" to "%s", or warnings occurred during the compilation due to "%q". \n' "${cppSourceFilePath}" "${cppBinaryFilePath}" "${compilationOutputs}" >&2
			else
				echo "Failed to compile \"${cppSourceFilePath}\" to \"${cppBinaryFilePath}\", or warnings occurred during the compilation. " >&2
			fi
		fi
	done
done
exit ${compilationFlag}
