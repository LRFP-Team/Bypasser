#!/system/bin/sh
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly USER_DATA_DIRECTORY_PATH="/data/user"
readonly TERMUX_PACKAGE_NAME="com.termux"
readonly REPOSITORY_DIRECTORY_NAMES="LRFP"
readonly DEFAULT_DIRECTORY_MODE=755
readonly DEFAULT_FILE_MODE=644
readonly DEFAULT_SHELL_MODE=744

foundAnyUser="false"
exitStatus=${EXIT_SUCCESS}
echo "The execution has started. "
echo ""
for entry in "${USER_DATA_DIRECTORY_PATH}"/*;
do
	test -e "${entry}" || continue # avoid no directories under ${USER_DATA_DIRECTORY_PATH}
	test -L "${entry}" && continue
	test -d "${entry}" || continue
	userID="${entry##*/}"
	case "${userID}" in
		*[!0-9]*)
			continue
			;;
	esac
	foundAnyUser="true"
	echo "- Detected User ${userID} under \"${USER_DATA_DIRECTORY_PATH}\". "
	termuxDataDirectoryPath="${entry}/${TERMUX_PACKAGE_NAME}"
	termuxInstalled="false"
	termuxUID=""
	if test -d "${termuxDataDirectoryPath}";
	then
		termuxInstalled="true"
		termuxUID="$(stat -c "%u" "${termuxDataDirectoryPath}" 2>/dev/null | head -n 1)"
	fi
	if test "true" = "${termuxInstalled}" && echo "${termuxUID}" | grep -qE '^[1-9][0-9]+$';
	then
		echo "  - The UID of Termux for User ${userID} is ${termuxUID}. "
		termuxHomeDirectoryPath="${termuxDataDirectoryPath}/files/home"
		if test -d "${termuxHomeDirectoryPath}";
		then
			echo "    - Detected the home directory \"${termuxHomeDirectoryPath}\". "
			if chown -R "${termuxUID}:${termuxUID}" "${termuxHomeDirectoryPath}";
			then
				echo "      - Successfully changed the owner and user group to Termux for all the directories and files under \"${termuxHomeDirectoryPath}\". "
			else
				exitStatus=${EXIT_FAILURE}
				echo "      - Failed to change the owner and user group to Termux for some or all of the directories and files under \"${termuxHomeDirectoryPath}\". "
			fi
			for repositoryDirectoryName in ${REPOSITORY_DIRECTORY_NAMES}
			do
				case "${repositoryDirectoryName}" in
					.|..|.git|.github)
						continue
						;;
				esac
				repositoryDirectoryPath="${termuxHomeDirectoryPath}/${repositoryDirectoryName}"
				if echo "${repositoryDirectoryName}" | grep -qE '^[.0-9A-Za-z_-]{1,100}$' && test -d "${repositoryDirectoryPath}";
				then
					echo "      - Detected the repository \"${repositoryDirectoryName}\" under \"${termuxHomeDirectoryPath}\". "
					if test -z "$(find "${repositoryDirectoryPath}" -type d -exec chmod ${DEFAULT_DIRECTORY_MODE} {} \; 2>&1)";
					then
						echo "        - Successfully changed the mode to ${DEFAULT_DIRECTORY_MODE} for all the directories under \"${repositoryDirectoryPath}\". "
					else
						exitStatus=${EXIT_FAILURE}
						echo "        - Failed to change the mode to ${DEFAULT_DIRECTORY_MODE} for some or all of the directories under \"${repositoryDirectoryPath}\". "
					fi
					if test -z "$(find "${repositoryDirectoryPath}" -type f ! -name "*.bat" ! -name "*.cmd" ! -name "*.sh" -exec chmod ${DEFAULT_FILE_MODE} {} \; 2>&1)";
					then
						echo "        - Successfully changed the mode to ${DEFAULT_FILE_MODE} for all the files under \"${repositoryDirectoryPath}\". "
					else
						exitStatus=${EXIT_FAILURE}
						echo "        - Failed to change the mode to ${DEFAULT_FILE_MODE} for some or all of the files under \"${repositoryDirectoryPath}\". "
					fi
					if test -z "$(find "${repositoryDirectoryPath}" -maxdepth 2 -type f \( -name "*.bat" -o -name "*.cmd" -o -name "*.sh" \) -exec chmod ${DEFAULT_SHELL_MODE} {} \; 2>&1)";
					then
						echo "        - Successfully changed the mode to ${DEFAULT_SHELL_MODE} for all the shell scripts under \"${repositoryDirectoryPath}\". "
					else
						exitStatus=${EXIT_FAILURE}
						echo "        - Failed to change the mode to ${DEFAULT_SHELL_MODE} for some or all of the shell scripts under \"${repositoryDirectoryPath}\". "
					fi
				fi
			done
		else
			echo "    - Skipped \"${termuxHomeDirectoryPath}\" as it does not exist. "
		fi
	elif test "false" = "${termuxInstalled}";
	then
		echo "  - Termux was not installed for User ${userID}. "
	else
		echo "  - Failed to obtain the UID of Termux for User ${userID}. "
		exitStatus=${EXIT_FAILURE}
	fi
done
if test "false" = "${foundAnyUser}";
then
	echo "No users were found under \"${USER_DATA_DIRECTORY_PATH}\". "
	exitStatus=${EXIT_FAILURE}
fi
echo ""
echo "The execution is finished (${exitStatus}). "
exit ${exitStatus}
