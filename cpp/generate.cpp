#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <set>
#include <regex>
#include "nlohmann/json.hpp" // https://github.com/nlohmann/json
#include "madler/unzip.h" // https://github.com/madler/zlib/blob/develop/contrib/minizip
#ifndef MODULE_NAME
#define MODULE_NAME "Bypasser"
#endif
#ifndef CPP_VERSION
#define CPP_VERSION "3.8.5.5+HKT20260509000000000000000"
#endif
#ifndef REGEX_PATTERN
#define REGEX_PATTERN "^[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+$"
#endif


enum class LogLevel : unsigned char
{
	All = 0, 
	Trace = 1, 
	Debug = 2, 
	Info = 3, 
	Warning = 4, 
	Error = 5, 
	Fatal = 6, 
	Off = 7
};


class Generator
{
private:
	static const std::string DefaultDatabaseFilePath = "database.json";
	static const LogLevel DefaultLevel = LogLevel::Warning;
	inline static const std::regex Pattern(REGEX_PATTERN);
	static const std::vector<std::string> ApplicationPartitions{ "/data", "/product", "/system", "/system_ext", "/vendor" };
	static const std::vector<std::string> ApplicationDirectoryNames{ "app", "app-private", "priv-app" };
	static const std::string HexadecimalCharacterSet = "0123456789ABCDEF";
	
	unsigned short flag = 0 /* 0b 0000 0000 0000 0000 */;
	std::string inputDatabaseFilePath = Generator::DefaultDatabaseFilePath;
	LogLevel logLevel = Generator::DefaultLevel;
	std::string outputHmaV92WhitelistFilePath{};
	std::string outputHmaV92BlacklistFilePath{};
	std::string outputHmaV93WhitelistFilePath{};
	std::string outputHmaV93BlacklistFilePath{};
	std::string outputHmaossV93WhitelistFilePath{};
	std::string outputHmaossV93BlacklistFilePath{};
	std::string outputPathTesterFilePath{};
	std::string outputTrickyStoreTargetFilePath{};
	const std::vector<std::string> helpArguments{ "h", "/h", "-h", "help", "/help", "--help" };
	const std::vector<std::string> inputDatabaseArguments{ "i", "/i", "-i", "inputDatabase", "/inputDatabase", "--inputDatabase" };
	const std::vector<std::string> logLevelArguments{ "l", "/l", "-l", "logLevel", "/logLevel", "--logLevel" };
	const std::vector<std::string> outputHmaV92WhitelistArguments{ "oa92w", "/oa92w", "-oa92w", "outputHmaV92Whitelist", "/outputHmaV92Whitelist", "--outputHmaV92Whitelist" };
	const std::vector<std::string> outputHmaV92BlacklistArguments{ "oa92b", "/oa92b", "-oa92b", "outputHmaV92Blacklist", "/outputHmaV92Blacklist", "--outputHmaV92Blacklist" };
	const std::vector<std::string> outputHmaV93WhitelistArguments{ "oa93w", "/oa93w", "-oa93w", "outputHmaV93Whitelist", "/outputHmaV93Whitelist", "--outputHmaV93Whitelist" };
	const std::vector<std::string> outputHmaV93BlacklistArguments{ "oa93b", "/oa93b", "-oa93b", "outputHmaV93Blacklist", "/outputHmaV93Blacklist", "--outputHmaV93Blacklist" };
	const std::vector<std::string> outputHmaossV93WhitelistArguments{ "os93w", "/os93w", "-os93w", "outputHmaossV93Whitelist", "/outputHmaossV93Whitelist", "--outputHmaossV93Whitelist" };
	const std::vector<std::string> outputHmaossV93BlacklistArguments{ "os93b", "/os93b", "-os93b", "outputHmaossV93Blacklist", "/outputHmaossV93Blacklist", "--outputHmaossV93Blacklist" };
	const std::vector<std::string> outputPathTesterArguments{ "op", "/op", "-op", "outputPathTester", "/outputPathTester", "--outputPathTester" };
	const std::vector<std::string> outputTrickyStoreTargetArguments{ "ot", "/ot", "-ot", "outputTrickyStoreTarget", "/outputTrickyStoreTarget", "--outputTrickyStoreTarget" };
	nlohmann::json j{};
	
	std::string vector2string(const std::vector<std::string>& arguments, const std::string& prefix, const std::string& separator, const std::string& suffix) const
	{
		std::string s = prefix;
		if (!arguments.empty())
		{
			s += arguments[0];
			const size_t length = arguments.size();
			for (size_t i = 1; i < length; ++i)
				s += separator + arguments[i];
		}
		s += suffix;
		return s;
	}
	std::string vector2string(const std::vector<std::string>& arguments) const { return this->vector2string(arguments, "[", "|", "]"); }
	std::string logLevel2string(const LogLevel level)
	{
		switch (level)
		{
		case LogLevel::All:
			return "All (" + std::to_string(static_cast<unsigned int>(LogLevel::All)) + ")";
		case LogLevel::Trace:
			return "Trace (" + std::to_string(static_cast<unsigned int>(LogLevel::Trace)) + ")";
		case LogLevel::Debug:
			return "Debug (" + std::to_string(static_cast<unsigned int>(LogLevel::Debug)) + ")";
		case LogLevel::Info:
			return "Info (" + std::to_string(static_cast<unsigned int>(LogLevel::Info)) + ")";
		case LogLevel::Warning:
			return "Warning (" + std::to_string(static_cast<unsigned int>(LogLevel::Warning)) + ")";
		case LogLevel::Error:
			return "Error (" + std::to_string(static_cast<unsigned int>(LogLevel::Error)) + ")";
		case LogLevel::Fatal:
			return "Fatal (" + std::to_string(static_cast<unsigned int>(LogLevel::Fatal)) + ")";
		default:
			return "Off (" + std::to_string(static_cast<unsigned int>(LogLevel::Off)) + ")";
		}
	}
	void printHelp() const
	{
		std::cout << "This is a generator for the " << MODULE_NAME << " rooting-layer system module. " << std::endl << std::endl;
		std::cout << "Options: " << std::endl;
		std::cout << "\t" << this->vector2string(this->helpArguments) << "\t\tPrint the help information. " << std::endl;
		std::cout << "\t" << this->vector2string(this->inputDatabaseArguments) << "<path>\t\tSpecify the input database JSON file path. The default value is \"" << Generator::DefaultDatabaseFilePath << "\". " << std::endl;
		std::cout << "\t" << this->vector2string(this->logLevelArguments) << "<level>\t\tSpecify the log level (std::cerr) from " << this->logLevel2string(LogLevel::All) << " to " << this->logLevel2string(LogLevel::Off) << ". The default value is " << this->logLevel2string(Generator::DefaultLevel) << ". " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputHmaV92WhitelistArguments) << "<path>\t\tSpecify the output HMA v92 whitelist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputHmaV92BlacklistArguments) << "<path>\t\tSpecify the output HMA v92 blacklist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputHmaV93WhitelistArguments) << "<path>\t\tSpecify the output HMA v93 whitelist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputHmaV93BlacklistArguments) << "<path>\t\tSpecify the output HMA v93 blacklist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputHmaossV93WhitelistArguments) << "<path>\t\tSpecify the output HMA-OSS v93 whitelist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputHmaossV93BlacklistArguments) << "<path>\t\tSpecify the output HMA-OSS v93 blacklist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputPathTesterArguments) << "<path>\t\tSpecify the output path tester shell script file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputTargetArguments) << "<path>\t\tSpecify the output Tricky Store target text file path. " << std::endl << std::endl;
		std::cout << "Notes:" << std::endl;
		std::cout << "\t1) All the arguments are optional and processed sequentially. If the same argument is provided multiple times, the last valid one will overwrite the previous ones. Unrecognized arguments, invalid argument values, or missing argument values will be skipped with a warning. " << std::endl;
		std::cout << "\t2) If an input path is not specified, the program will use the corresponding default value. The program will return EOF (" << EOF << ") if the input database JSON file cannot be parsed. Parsing failures for other inputs will be skipped, and a warning will be issued. " << std::endl;
		std::cout << "\t3) The program will create the parent directory for each output path if it does not exist. If ``.`` is passed for an output path, the program will print the generation result to the console. If an output path is not specified, the corresponding generation will be skipped. Only when all the requested outputs succeed will the program return EXIT_SUCCESS (" << EXIT_SUCCESS << "). Otherwise, the program will return EXIT_FAILURE (" << EXIT_FAILURE << "). " << std::endl << std::endl;
		return;
	}
	bool print(const std::string& content, const LogLevel level) const
	{
		if (level >= this->logLevel)
			switch (level)
			{
			case LogLevel::Trace:
				std::cerr << "Trace: " << content << std::endl;
				return true;
			case LogLevel::Debug:
				std::cerr << "Debug: " << content << std::endl;
				return true;
			case LogLevel::Info:
				std::cerr << "Info: " << content << std::endl;
				return true;
			case LogLevel::Warning:
				std::cerr << "Warning: " << content << std::endl;
				return true;
			case LogLevel::Error:
				std::cerr << "Error: " << content << std::endl;
				return true;
			case LogLevel::Fatal:
				std::cerr << "Fatal: " << content << std::endl;
				return true;
			default:
				return false;
			}
		else
			return false;
	}
	bool checkoutApplication(const std::string& apkFilePath, bool& isPlugin) const
	{
		unzFile archive = unzOpen(apkFilePath.c_str());
		if (archive)
		{
			isPlugin = false;
			if (unzLocateFile(archive, "assets/xposed_init", 0) == UNZ_OK)
			{
				unz_file_info pluginInformation;
				if (unzGetCurrentFileInfo(archive, &pluginInformation, nullptr, 0, nullptr, 0, nullptr, 0) == UNZ_OK && pluginInformation.uncompressed_size > 0)
					isPlugin = true;
			}
			unzClose(archive);
			return true;
		}
		else
			return false;
	}
	std::string formatMessage(const std::string& message) const
	{
		std::string formattedMessage = "\"";
		for (unsigned char character : message)
			switch (character)
			{
			case '\a': // \x07
				formattedMessage += "\\a";
				break;
			case '\b': // 0x08
				formattedMessage += "\\b";
				break;
			case '\t': // \x09
				formattedMessage += "\\t";
				break;
			case '\n': // \x0A
				formattedMessage += "\\n";
				break;
			case '\v': // \x0B
				formattedMessage += "\\v";
				break;
			case '\f': // \x0C
				formattedMessage += "\\f";
				break;
			case '\r': // \x0D
				formattedMessage += "\\r";
				break;
			case '\"':
			case '\'':
			case '\\':
				formattedMessage += "\\" + character;
				break;
			default:
				if (character <= 31 || 127 == character)
					formattedMessage += "\\x" + std::string(1, Generator::HexadecimalCharacterSet[character >> 4]) + std::string(1, Generator::HexadecimalCharacterSet[character & 15/* 0b 0000 1111 */]);
				else
					formattedMessage += character;
				break;
			}
		formattedMessage += "\"";
		return formattedMessage;
	}
	bool traverseUserApplicationDirectory(const std::string& userApplicationDirectoryPath, size_t& newPluginCount, size_t& newNonPluginCount)
	{
		std::filesystem::path directoryPath(userApplicationDirectoryPath);
		if (std::filesystem::exists(directoryPath) && std::filesystem::is_directory(directoryPath))
		{
			/**
			 * formCount = directoryFormCount + fileFormCount + invalidFormCount
			 * directoryFormCount = validDirectoryFormCount + invalidDirectoryFormCount + failureInstallationCount
			 * validDirectoryFormCount = validDirectoryFormSuccessCount + validDirectoryFormFailureCount
			 * failureInstallationCount = failureInstallationRemovedCount + failureInstallationUnremovedCount
			 * fileFormCount = validFileFormCount + invalidFileFormCount
			 */
			size_t formCount = 0, directoryFormCount = 0, validDirectoryFormCount = 0, validDirectoryFormSuccessCount = 0, validDirectoryFormFailureCount = 0, invalidDirectoryFormCount = 0, failureInstallationCount = 0, failureInstallationRemovedCount = 0, failureInstallationUnremovedCount = 0, fileFormCount = 0, validFileFormCount = 0, invalidFileFormCount = 0, invalidFormCount = 0;
			try
			{
				for (const std::filesystem::directory_entry& firstLayerEntry : std::filesystem::directory_iterator(directoryPath))
				{
					++formCount;
					if (firstLayerEntry.is_symlink())
						++invalidFormCount;
					else if (firstLayerEntry.is_directory())
					{
						/* Analyze the application installed as a directory */
						++directoryFormCount;
						std::string directoryName = firstLayerEntry.path().filename().string();
						const size_t directoryNameLength = directoryName.length();
						if (directoryNameLength >= 9 && 'v' == directoryName[0] && 'm' == directoryName[1] && 'd' == directoryName[2] && 'l' == directoryName[3] && '.' == directoryName[directoryNameLength - 4] && 't' == directoryName[directoryNameLength - 3] && 'm' == directoryName[directoryNameLength - 2] && 'p' == directoryName[directoryNameLength - 1])
						{
							/* Remove ``vmdl*.tmp`` directories */
							++failureInstallationCount;
							std::error_code errorCode{};
							std::filesystem::remove_all(firstLayerEntry.path(), errorCode);
							if (errorCode)
								++failureInstallationUnremovedCount;
							else
								++failureInstallationRemovedCount;
						}
						else
						{
							bool isValid = 26 == directoryNameLength && '~' == directoryName[0] && '~' == directoryName[1] && '=' == directoryName[24] && '=' == directoryName[25];
							for (size_t i = 2; i < 24 && isValid; ++i)
								if (!(('A' <= directoryName[i] && directoryName[i] <= 'Z') || ('a' <= directoryName[i] && directoryName[i] <= 'z') || ('0' <= directoryName[i] && directoryName[i] <= '9') || '_' == directoryName[i] || '-' == directoryName[i]))
									isValid = false;
							if (isValid)
							{
								/* Enter the second-layer directory */
								std::filesystem::directory_entry secondLayerEntry{};
								for (std::filesystem::directory_iterator directoryIt = std::filesystem::directory_iterator(firstLayerEntry.path()); directoryIt != std::filesystem::directory_iterator(); ++directoryIt)
									if (!directoryIt->is_symlink() && directoryIt->is_directory())
										if (secondLayerEntry.path().empty())
											secondLayerEntry = *directoryIt;
										else
										{
											++invalidDirectoryFormCount;
											isValid = false;
										}
									else
									{
										++invalidDirectoryFormCount;
										isValid = false;
									}
								if (isValid)
								{
									std::string packageName = secondLayerEntry.path().filename().string();
									const size_t packageNameLength = packageName.length();
									size_t position = packageName.find('-');
									if (std::string::npos == position || position > packageNameLength - 3)
										++invalidDirectoryFormCount;
									else if ('=' == packageName[packageNameLength - 1] && '=' == packageName[packageNameLength - 2])
									{
										for (size_t i = packageNameLength - 2; i < packageNameLength; ++i)
											if (!(('A' <= packageName[i] && packageName[i] <= 'Z') || ('a' <= packageName[i] && packageName[i] <= 'z') || ('0' <= packageName[i] && packageName[i] <= '9') || '_' == packageName[i] || '-' == packageName[i]))
											{
												isValid = false;
												break;
											}
										if (isValid)
										{
											packageName = packageName.substr(0, position);
											if (std::regex_match(packageName, Generator::Pattern))
											{
												/* Enter the third-layer directory */
												std::filesystem::directory_entry thirdLayerEntry{};
												for (std::filesystem::directory_iterator directoryIt = std::filesystem::directory_iterator(secondLayerEntry.path()); directoryIt != std::filesystem::directory_iterator(); ++directoryIt)
												{
													if (directoryIt->is_symlink())
													{
														++invalidDirectoryFormCount;
														isValid = false;
														break;
													}
													else if (directoryIt->is_directory())
													{
														if ("lib" != directoryIt->path().filename().string() && "oat" != directoryIt->path().filename().string())
														{
															++invalidDirectoryFormCount;
															isValid = false;
															break;
														}
													}
													else if (directoryIt->is_regular_file())
													{
														if ("base.apk" == directoryIt->path().filename().string())
															thirdLayerEntry = *directoryIt;
													}
													else
													{
														++invalidDirectoryFormCount;
														isValid = false;
														break;
													}
												}
												if (isValid)
												{
													++validDirectoryFormCount;
													bool isPlugin = false;
													if (this->checkoutApplication(thirdLayerEntry.path().string(), isPlugin))
													{
														++validDirectoryFormSuccessCount;
														if (isPlugin)
														{
															if (std::find(this->j["M"].begin(), this->j["M"].end(), packageName) == this->j["M"].end())
															{
																this->j["M"].push_back(packageName);
																std::sort(this->j["M"].begin(), this->j["M"].end());
																++newPluginCount;
															}
														}
														else
														{
															bool alreadyInDatabase = false;
															for (nlohmann::json::const_iterator databaseIt = this->j["D"].begin(); databaseIt != this->j["D"].end(); ++databaseIt)
																if (databaseIt->is_object() && databaseIt->contains("P") && (*databaseIt)["P"].is_string() && packageName == (*databaseIt)["P"].get<std::string>())
																{
																	alreadyInDatabase = true;
																	break;
																}
															++newNonPluginCount;
														}
													}
													else
													{
														this->print("Failed to checkout " + this->formatMessage(thirdLayerEntry.path().string()) + ". ", LogLevel::Warning);
														++validDirectoryFormFailureCount;
													}
												}
											}
											else
												++invalidDirectoryFormCount;
										}
										else
											++invalidDirectoryFormCount;
									}
									else
										++invalidDirectoryFormCount;
								}
								else
									++invalidDirectoryFormCount;
							}
							else
								++invalidDirectoryFormCount;
						}
					}
					else if (firstLayerEntry.is_regular_file())
					{
						/* Analyze the application installed as a file */
						++fileFormCount;
						const std::string packageName = firstLayerEntry.path().stem().string();
						if (std::regex_match(packageName, Generator::Pattern))
						{

						}
						else
							++invalidFileFormCount;
					}
					else
						++invalidFormCount;
			}
			catch (...)
			{
				return false;
			}

			// 杈撳嚭缁熻缁撴灉锛堝疄闄呴」鐩腑鍙浛鎹负瀛樺偍鍒板閮ㄥ鍣ㄦ垨閫氳繃鍥炶皟杩斿洖锛?			std::cout << "Folder-based applications count: " << folderAppCount << std::endl;
			for (const auto& name : folderPackageNames) {
				std::cout << "  Package: " << name << std::endl;
			}

			std::cout << "File-based applications count: " << fileAppCount << std::endl;
			for (const auto& name : filePackageNames) {
				std::cout << "  Package: " << name << std::endl;
			}

			return true;
		}
		else
			return false;
	}
	bool handleDirectory(const std::string& filePath)
	{
		try
		{
			std::filesystem::path p(filePath);
			const std::filesystem::path directoryPath = p.parent_path();
			if (directoryPath.empty()) // os.path.split("test.txt")[0] = ""
				return true;
			else if (std::filesystem::exists(directoryPath))
				return std::filesystem::is_directory(directoryPath);
			else
				return std::filesystem::create_directories(directoryPath) && std::filesystem::is_directory(directoryPath);
		}
		catch (...)
		{
			return false;
		}
	}
	std::string array2string(const nlohmann::json& elements, const std::string& prefix, const std::string& separator, const std::string& suffix) const
	{
		std::string s = prefix;
		for (nlohmann::json::const_iterator arrayIt = elements.begin(); arrayIt != elements.end(); ++arrayIt)
			if (arrayIt->is_string())
			{
				s += arrayIt->get<std::string>();
				for (++arrayIt; arrayIt != elements.end(); ++arrayIt)
					if (arrayIt->is_string())
						s += separator + arrayIt->get<std::string>();
				break;
			}
		s += suffix;
		return s;
	}
	
public:
	Generator()
	{
		
	}
	bool parseArguments(int argc, char* argv[], bool& exitFlag, const bool resetBeforeParsing) // 0b 0000 0000 0000 0000 | 0b 0000 0000 0000 0001 -> 0b 0000 0000 0000 0001
	{
		this->flag = 0 /* 0b 0000 0000 0000 0000 */;
		if (resetBeforeParsing)
		{
			this->inputDatabaseFilePath = Generator::DefaultDatabaseFilePath;
			this->inputDataApplicationDirectoryPath = Generator::DefaultDataApplicationDirectoryPath;
			this->inputProductApplicationDirectoryPath = Generator::DefaultProductApplicationDirectoryPath;
			this->inputSystemApplicationDirectoryPath = Generator::DefaultSystemApplicationDirectoryPath;
			this->inputVendorApplicationDirectoryPath = Generator::DefaultVendorApplicationDirectoryPath;
			this->logLevel = Generator::DefaultLogLevel;
			this->outputHmaV92WhitelistFilePath.clear();
			this->outputHmaV92BlacklistFilePath.clear();
			this->outputHmaV93WhitelistFilePath.clear();
			this->outputHmaV93BlacklistFilePath.clear();
			this->outputHmaossV93WhitelistFilePath.clear();
			this->outputHmaossV93BlacklistFilePath.clear();
			this->outputPathTesterFilePath.clear();
			this->outputTrickyStoreTargetFilePath.clear();
		}
		bool missingArgument = false;
		std::vector<size_t> invalidArgumentIndexes{};
		for (int i = 1; i < argc; ++i)
			if (std::find(helpArguments.begin(), helpArguments.end(), argv[i]) != helpArguments.end())
			{
				this->printHelp();
				exitFlag = true;
				return true;
			}
			else if (std::find(inputDatabaseArguments.begin(), inputDatabaseArguments.end(), argv[i]) != inputDatabaseArguments.end())
				if (++i < argc)
					this->inputDatabaseFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(logLevelArguments.begin(), logLevelArguments.end(), argv[i]) != logLevelArguments.end())
				if (++i < argc)
					if (argv[i].empty())
						this->print("The passed log level cannot be recognized, which has been skipped. ", LogLevel::Warning);
					else
						switch (argv[i][0])
						{
						case 'A':
						case 'a':
							this->logLevel = LogLevel::All;
							break;
						case 'T':
						case 't':
							this->logLevel = LogLevel::Trace;
							break;
						case 'D':
						case 'd':
							this->logLevel = LogLevel::Debug;
							break;
						case 'I':
						case 'i':
							this->logLevel = LogLevel::Info;
						case 'W':
						case 'w':
							this->logLevel = LogLevel::Warning;
							break;
						case 'E':
						case 'e':
							this->logLevel = LogLevel::Error;
							break;
						case 'F':
						case 'f':
							this->logLevel = LogLevel::Fatal;
							break;
						case 'O':
						case 'o':
							this->logLevel = LogLevel::Off;
							break;
						default:
							if (static_cast<char>(LogLevel::All) <= argv[i][0] && argv[i][0] <= static_cast<char>(LogLevel::Off))
								this->logLevel = static_cast<LogLevel>(argv[i][0]);
							else
								this->print("The passed log level cannot be recognized, which has been skipped. ", LogLevel::Warning);
							break;
						}
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaV92WhitelistArguments.begin(), outputHmaV92WhitelistArguments.end(), argv[i]) != outputHmaV92WhitelistArguments.end())
				if (++i < argc)
					this->outputHmaV92WhitelistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaV92BlacklistArguments.begin(), outputHmaV92BlacklistArguments.end(), argv[i]) != outputHmaV92BlacklistArguments.end())
				if (++i < argc)
					this->outputHmaV92BlacklistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaV93WhitelistArguments.begin(), outputHmaV93WhitelistArguments.end(), argv[i]) != outputHmaV93WhitelistArguments.end())
				if (++i < argc)
					this->outputHmaV93WhitelistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaV93BlacklistArguments.begin(), outputHmaV93BlacklistArguments.end(), argv[i]) != outputHmaV93BlacklistArguments.end())
				if (++i < argc)
					this->outputHmaV93BlacklistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaossV93WhitelistArguments.begin(), outputHmaossV93WhitelistArguments.end(), argv[i]) != outputHmaossV93WhitelistArguments.end())
				if (++i < argc)
					this->outputHmaossV93WhitelistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaossV93BlacklistArguments.begin(), outputHmaossV93BlacklistArguments.end(), argv[i]) != outputHmaossV93BlacklistArguments.end())
				if (++i < argc)
					this->outputHmaossV93BlacklistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputPathTesterArguments.begin(), outputPathTesterArguments.end(), argv[i]) != outputPathTesterArguments.end())
				if (++i < argc)
					this->outputPathTesterFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputTargetArguments.begin(), outputTargetArguments.end(), argv[i]) != outputTargetArguments.end())
				if (++i < argc)
					this->outputTrickyStoreTargetFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else
				invalidArgumentIndexes.push_back(i);
		if (missingArgument)
			this->print("The corresponding value for the last argument is missing. ", LogLevel::Warning);
		const size_t invalidArgumentCount = invalidArgumentIndexes.size();
		if (1 == invalidArgumentCount)
			this->print("The argument whose index is [" + std::to_string(invalidArgumentIndexes[0]) + "] could not be recognized, which has been skipped. ", LogLevel::Warning);
		else if (invalidArgumentCount >= 2)
		{
			std::string message = std::to_string(invalidArgumentIndexes.size()) + " arguments, whose indexes are ";
			if (2 == invalidArgumentCount)
				message += "[" + std::to_string(invalidArgumentIndexes[0]) + "] and [" + std::to_string(invalidArgumentIndexes[1]) + "]";
			else
			{
				for (size_t i = 0; i < invalidArgumentCount - 1; ++i)
					message += "[" + std::to_string(invalidArgumentIndexes[i]) + "], ";
				message += "and [" + std::to_string(invalidArgumentIndexes[invalidArgumentCount - 1]) + "]";
			}
			this->print(message + ", could not be recognized, which have been skipped. ", LogLevel::Warning);
		}
		if (this->inputDatabaseFilePath.empty())
			return false;
		else
		{
			this->flag = 1/* 0b 0000 0000 0000 0001 */;
			return true;
		}
	}
	bool parseArguments(int argc, char* argv[], bool& exitFlag) { return this->parseArguments(argc, argv, exitFlag, true); }
	bool parseJSON() // 0b 0000 0000 0000 0001 | 0b 0000 0000 0000 0010 -> 0b 0000 0000 0000 0011
	{
		if (this->flag & 1/* 0b 0000 0000 0000 0001 */)
		{
			this->flag &= 1/* 0b 0000 0000 0000 0001 */;
			try
			{
				std::ifstream inputDatabaseFile(this->inputDatabaseFilePath);
				if (inputDatabaseFile.is_open())
				{
					try
					{
						this->j = nlohmann::json::parse(inputDatabaseFile);
						
						/* First-level */
						const std::vector<std::string> keysToKeep{ "C", "D", "M", "N", "S", "T", "U", "V" };
						int removedKeyCount = 0;
						for (nlohmann::json::iterator entryIt = this->j.begin(); entryIt != this->j.end(); )
							if (std::find(keysToKeep.begin(), keysToKeep.end(), entryIt.key()) != keysToKeep.end())
								++entryIt;
							else
							{
								entryIt = this->j.erase(entryIt);
								++removedKeyCount;
							}
						const std::string cppVersion = [] { const std::string v(CPP_VERSION); const size_t position = v.find('+'); return std::string::npos == position ? v + "+" : v.substr(0, position + 1); }();
						if (this->j.contains("V") && this->j["V"].is_string() && this->j["V"].get<std::string>().substr(0, cppVersion.length()) == cppVersion)
							if (this->j.contains("U") && this->j["U"].is_string() && REGEX_PATTERN == this->j["U"].get<std::string>())
							{
								if (1 == removedKeyCount)
									this->print("A root key is invalid, which has been removed. ", LogLevel::Warning);
								else if (removedKeyCount)
									this->print(std::to_string(removedKeyCount) + " root keys are invalid, which have been removed. ", LogLevel::Warning);
							}
							else
								this->print("This program expects the regex pattern \"" + std::string(REGEX_PATTERN) + "\" while the input database is not. ", LogLevel::Warning);
						else
							this->print("This program expects the version " + std::string(CPP_VERSION) + " while the input database is not, which may result in warnings. ", LogLevel::Warning);
						
						/* Second-level */
						removedKeyCount = 0;
						if (this->j.contains("C") && this->j["C"].is_object())
						{
							if (this->j["C"].contains("") && this->j["C"][""].is_array() && this->j["C"].contains("_") && this->j["C"]["_"].is_object())
							{
								for (nlohmann::json::iterator entryIt = this->j["C"]["_"].begin(); entryIt != this->j["C"]["_"].end(); )
									if (entryIt.key().length() == 1 && 'A' <= entryIt.key()[0] && entryIt.key()[0] <= 'Z' && entryIt.value().is_array())
									{
										int removedValueCount = 0;
										for (nlohmann::json::iterator arrayIt = entryIt.value().begin(); arrayIt != entryIt.value().end(); )
											if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), Generator::Pattern))
												++arrayIt;
											else
											{
												arrayIt = entryIt.value().erase(arrayIt);
												++removedValueCount;
											}
										if (1 == removedValueCount)
											this->print("A value in $C_" + entryIt.key() + "$ is invalid, which has been removed. ", LogLevel::Warning);
										else if (removedValueCount)
											this->print(std::to_string(removedValueCount) + " values in $C_" + entryIt.key() + "$ are invalid, which have been removed. ", LogLevel::Warning);
										++entryIt;
									}
									else if (!(regex_match(entryIt.key(), Generator::Pattern) && entryIt.value().is_null()))
									{
										entryIt = this->j["C"]["_"].erase(entryIt);
										++removedKeyCount;
									}
								if (1 == removedKeyCount)
									this->print("A key in $C$ is invalid, which has been removed. ", LogLevel::Warning);
								else if (removedKeyCount)
									this->print(std::to_string(removedKeyCount) + " keys in $C$ are invalid, which have been removed. ", LogLevel::Warning);
							}
							else

						}
						else
						{
							this->j["C"] = nlohmann::json::object();
							this->print("Initialized $C$ as an empty dictionary. ", LogLevel::Warning);
						}
						if (this->j.contains("D") && this->j["D"].is_array())
						{
							int removedValueCount = 0;
							for (nlohmann::json::iterator arrayIt = this->j["D"].begin(); arrayIt != this->j["D"].end(); )
								if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), Generator::Pattern))
									++arrayIt;
								else
								{
									arrayIt = this->j["D"].erase(arrayIt);
									++removedValueCount;
								}
							if (1 == removedValueCount)
								this->print("A value in $D$ is invalid, which has been removed. ", LogLevel::Warning);
							else if (removedValueCount)
								this->print(std::to_string(removedValueCount) + " values in $D$ are invalid, which have been removed. ", LogLevel::Warning);
						}
						else
						{
							this->j["D"] = nlohmann::json::array();
							this->print("Initialized $D$ as an empty array. ", LogLevel::Warning);
						}
						if (this->j.contains("M") && this->j["M"].is_array())
						{
							int removedValueCount = 0;
							for (nlohmann::json::iterator arrayIt = this->j["M"].begin(); arrayIt != this->j["M"].end(); )
								if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), Generator::Pattern))
									++arrayIt;
								else
								{
									arrayIt = this->j["M"].erase(arrayIt);
									++removedValueCount;
								}
							if (1 == removedValueCount)
								this->print("A value in $M$ is invalid, which has been removed. ", LogLevel::Warning);
							else if (removedValueCount)
								this->print(std::to_string(removedValueCount) + " values in $M$ are invalid, which have been removed. ", LogLevel::Warning);
						}
						else
						{
							this->j["M"] = nlohmann::json::array();
							this->print("Initialized $M$ as an empty array. ", LogLevel::Warning);
						}
						removedKeyCount = 0;
						if (this->j.contains("N") && this->j["N"].is_object())
						{
							for (nlohmann::json::iterator outerEntryIt = this->j["N"].begin(); outerEntryIt != this->j["N"].end(); )
								if (std::regex_match(outerEntryIt.key(), Generator::Pattern) && outerEntryIt.value().is_object())
								{
									int removedEntryCount = 0;
									for (nlohmann::json::iterator innerEntryIt = outerEntryIt.value().begin(); innerEntryIt != outerEntryIt.value().end(); )
										if (std::regex_match(innerEntryIt.key(), Generator::Pattern) && innerEntryIt.value().is_boolean())
											++innerEntryIt;
										else
										{
											innerEntryIt = outerEntryIt.value().erase(innerEntryIt);
											++removedEntryCount;
										}
									if (1 == removedEntryCount)
										this->print("An entry in " + outerEntryIt.key() + " of $N$ is invalid, which has been removed. ", LogLevel::Warning);
									else if (removedEntryCount)
										this->print(std::to_string(removedEntryCount) + " entries in " + outerEntryIt.key() + " of $N$ are invalid, which have been removed. ", LogLevel::Warning);
									++outerEntryIt;
								}
								else
								{
									outerEntryIt = this->j["N"].erase(outerEntryIt);
									++removedKeyCount;
								}
							if (1 == removedKeyCount)
								this->print("A key in $N$ is invalid, which has been removed. ", LogLevel::Warning);
							else if (removedKeyCount)
								this->print(std::to_string(removedKeyCount) + " keys in $N$ are invalid, which have been removed. ", LogLevel::Warning);
						}
						else
						{
							this->j["N"] = nlohmann::json::object();
							this->print("Initialized $N$ as an empty dictionary. ", LogLevel::Warning);
						}
						if (this->j.contains("S") && this->j["S"].is_array())
						{
							int removedValueCount = 0;
							for (nlohmann::json::iterator arrayIt = this->j["S"].begin(); arrayIt != this->j["S"].end(); )
								if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), Generator::Pattern))
									++arrayIt;
								else
								{
									arrayIt = this->j["S"].erase(arrayIt);
									++removedValueCount;
								}
							if (1 == removedValueCount)
								this->print("A value in $S$ is invalid, which has been removed. ", LogLevel::Warning);
							else if (removedValueCount)
								this->print(std::to_string(removedValueCount) + " values in $S$ are invalid, which have been removed. ", LogLevel::Warning);
						}
						else
						{
							this->j["S"] = nlohmann::json::array();
							this->print("Initialized $S$ as an empty array. ", LogLevel::Warning);
						}
						if (this->j.contains("T") && this->j["T"].is_object())
						{
							int removedEntryCount = 0;
							for (nlohmann::json::iterator entryIt = this->j["T"].begin(); entryIt != this->j["T"].end(); )
								if (std::regex_match(entryIt.key(), Generator::Pattern) && entryIt.value().is_boolean())
									++entryIt;
								else
									entryIt = this->j["T"].erase(entryIt);
							if (1 == removedEntryCount)
								this->print("An entry in $T$ is invalid, which has been removed. ", LogLevel::Warning);
							else if (removedEntryCount)
								this->print(std::to_string(removedEntryCount) + " entries in $T$ are invalid, which have been removed. ", LogLevel::Warning);
						}
						else
						{
							this->j["T"] = nlohmann::json::object();
							this->print("Initialized $T$ as an empty dictionary. ", LogLevel::Warning);
						}
						this->flag |= 2/* 0b 0000 0000 0000 0010 */;
					}
					catch (...)
					{
						this->print("Failed to parse the content read from the input database JSON file. ", LogLevel::Error);
					}
					inputDatabaseFile.close();
					return this->flag & 2/* 0b 0000 0000 0000 0010 */ && this->flag & 1/* 0b 0000 0000 0000 0001 */;
				}
				else
				{
					this->print("Failed to open the input database JSON file. ", LogLevel::Error);
					return false;
				}
			}
			catch (...)
			{
				this->print("Failed to parse the input database JSON file. ", LogLevel::Error);
				return false;
			}
		}
		else
		{
			this->print("Please parse command-line arguments before paring the input database JSON file. ", LogLevel::Error);
			return false;
		}
	}
	bool scanApplicationDirectories() // 0b 0000 0000 0000 0011 | 0b 0000 0000 0011 1100 -> 0b 0000 0000 0011 1111
	{
		if (this->flag & 2/* 0b 0000 0000 0000 0010 */ && this->flag & 1/* 0b 0000 0000 0000 0001 */)
		{
			this->flag &= 3/* 0b 0000 0000 0000 0011 */;
			size_t newPluginCount = 0, newNonPluginCount = 0;
			if (this->traverseApplicationDirectory(this->inputDataApplicationDirectoryPath, newPluginCount, newNonPluginCount))
				this->flag |= 4/* 0b 0000 0000 0000 0100 */;
			if (this->traverseApplicationDirectory(this->inputProductApplicationDirectoryPath, newPluginCount, newNonPluginCount))
				this->flag |= 8/* 0b 0000 0000 0000 1000 */;
			if (this->traverseApplicationDirectory(this->inputSystemApplicationDirectoryPath, newPluginCount, newNonPluginCount))
				this->flag |= 16/* 0b 0000 0000 0001 0000 */;
			if (this->traverseApplicationDirectory(this->inputVendorApplicationDirectoryPath, newPluginCount, newNonPluginCount))
				this->flag |= 32/* 0b 0000 0000 0010 0000 */;
			return this->flag && 32/* 0b 0000 0000 0010 0000 */ && this->flag & 16/* 0b 0000 0000 0001 0000 */ && this->flag & 8/* 0b 0000 0000 0000 1000 */ && this->flag & 4/* 0b 0000 0000 0000 0100 */ && this->flag & 2/* 0b 0000 0000 0000 0010 */ && this->flag & 1/* 0b 0000 0000 0000 0001 */;
		}
		else
		{
			this->print("Please parse the input database JSON file before scanning application directories. ", LogLevel::Error);
			return false;
		}
	}
	bool generateHMAConfigurations() // 0b ???? ??00 0011 1111 | 0b 0000 0011 1100 0000 -> 0b ???? ??11 1111 1111
	{
		if (this->flag & 2/* 0b 0000 0000 0000 0010 */ && this->flag & 1/* 0b 0000 0000 0000 0001 */)
		{
			this->flag &= 243/* 0b 1111 0011 */;
			if (this->outputHmaV92WhitelistFilePath.empty() && this->outputHmaV92BlacklistFilePath.empty())
				this->flag |= 12/* 0b00001100 */;
			else
			{
				/* hmaConfiguration */
				nlohmann::ordered_json hmaConfiguration{};
				hmaConfiguration["configVersion"] = 92;
				hmaConfiguration["detailLog"] = true;
				hmaConfiguration["maxLogSize"] = 1024;
				hmaConfiguration["forceMountData"] = true;
				hmaConfiguration["aggressiveFilter"] = true;
				hmaConfiguration["templates"] = nlohmann::ordered_json::object();
				for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
				{
					const std::string whitelistName = "WhitelistC" + entryIt.key();
					hmaConfiguration["templates"][whitelistName] = nlohmann::ordered_json::object();
					hmaConfiguration["templates"][whitelistName]["isWhitelist"] = true;
					hmaConfiguration["templates"][whitelistName]["appList"] = nlohmann::ordered_json::array();
					for (const nlohmann::json& value : entryIt.value())
						hmaConfiguration["templates"][whitelistName]["appList"].push_back(value.get<std::string>());
				}
				for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
				{
					const std::string blacklistName = "BlacklistC" + entryIt.key();
					hmaConfiguration["templates"][blacklistName] = nlohmann::ordered_json::object();
					hmaConfiguration["templates"][blacklistName]["isWhitelist"] = false;
					hmaConfiguration["templates"][blacklistName]["appList"] = nlohmann::ordered_json::array();
					for (const nlohmann::json& value : entryIt.value())
						hmaConfiguration["templates"][blacklistName]["appList"].push_back(value.get<std::string>());
				}
				hmaConfiguration["templates"]["BlacklistD"] = nlohmann::ordered_json::object();
				hmaConfiguration["templates"]["BlacklistD"]["isWhitelist"] = false;
				hmaConfiguration["templates"]["BlacklistD"]["appList"] = nlohmann::ordered_json::array();
				for (const nlohmann::json& value : this->j["D"])
					hmaConfiguration["templates"]["BlacklistD"]["appList"].push_back(value.get<std::string>());
				hmaConfiguration["templates"]["BlacklistM"] = nlohmann::ordered_json::object();
				hmaConfiguration["templates"]["BlacklistM"]["isWhitelist"] = false;
				hmaConfiguration["templates"]["BlacklistM"]["appList"] = nlohmann::ordered_json::array();
				for (const nlohmann::json& value : this->j["M"])
					hmaConfiguration["templates"]["BlacklistM"]["appList"].push_back(value.get<std::string>());
				
				/* hmaV92WhitelistConfiguration */
				if (this->outputHmaV92WhitelistFilePath.empty())
					this->flag |= 4/* 0b00000100 */;
				else
				{
					nlohmann::ordered_json hmaV92WhitelistConfiguration(hmaConfiguration);
					hmaV92WhitelistConfiguration["scope"] = nlohmann::json::object();
					for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
						for (const nlohmann::json& value : entryIt.value())
						{
							const std::string packageName = value.get<std::string>();
							hmaV92WhitelistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
							hmaV92WhitelistConfiguration["scope"][packageName]["useWhitelist"] = true;
							hmaV92WhitelistConfiguration["scope"][packageName]["excludeSystemApps"] = true;
							hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
							hmaV92WhitelistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						}
					for (const nlohmann::json& value : this->j["D"])
					{
						const std::string packageName = value.get<std::string>();
						hmaV92WhitelistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
						hmaV92WhitelistConfiguration["scope"][packageName]["useWhitelist"] = true;
						hmaV92WhitelistConfiguration["scope"][packageName]["excludeSystemApps"] = true;
						hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
						for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
							hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
						hmaV92WhitelistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						hmaV92WhitelistConfiguration["scope"][packageName]["extraAppList"].push_back(packageName);
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["N"].begin(); outerEntryIt != this->j["N"].end(); ++outerEntryIt)
						if (hmaV92WhitelistConfiguration["scope"].contains(outerEntryIt.key()))
							for (nlohmann::json::const_iterator innerEntryIt = outerEntryIt.value().begin(); innerEntryIt != outerEntryIt.value().end(); ++innerEntryIt)
							{
								if (innerEntryIt.value().get<bool>()) // add to the ``extraAppList`` if it is not in any of the templates applied
								{
									bool addingFlag = !hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].contains(innerEntryIt.key());
									if (addingFlag)
										for (const nlohmann::ordered_json& value : hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["applyTemplates"])
										{
											const std::string templateName = value.get<std::string>();
											if (hmaV92WhitelistConfiguration["templates"].contains(templateName) && hmaV92WhitelistConfiguration["templates"][templateName].contains("isWhitelist") && hmaV92WhitelistConfiguration["templates"][templateName]["isWhitelist"].get<bool>() && hmaV92WhitelistConfiguration["templates"][templateName].contains("appList") && hmaV92WhitelistConfiguration["templates"][templateName]["appList"].contains(innerEntryIt.key()))
											{
												addingFlag = false;
												break;
											}
										}
									if (addingFlag)
										hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].push_back(innerEntryIt.key());
								}
								else // Search for all the whitelist-type template where the package name is located from the applied template list and unzip the templates to "extraAppList" without the package name
									for (nlohmann::ordered_json::iterator templateArrayIt = hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["applyTemplates"].begin(); templateArrayIt != hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["applyTemplates"].end(); )
									{
										const std::string templateName = templateArrayIt.value().get<std::string>();
										if (hmaV92WhitelistConfiguration["templates"].contains(templateName) && hmaV92WhitelistConfiguration["templates"][templateName].contains("isWhitelist") && hmaV92WhitelistConfiguration["templates"][templateName]["isWhitelist"].is_boolean() && hmaV92WhitelistConfiguration["templates"][templateName]["isWhitelist"].get<bool>() && hmaV92WhitelistConfiguration["templates"][templateName].contains("appList") && hmaV92WhitelistConfiguration["templates"][templateName]["appList"].is_array() && std::find(hmaV92WhitelistConfiguration["templates"][templateName]["appList"].begin(), hmaV92WhitelistConfiguration["templates"][templateName]["appList"].end(), innerEntryIt.key()) != hmaV92WhitelistConfiguration["templates"][templateName]["appList"].end())
										{
											for (const nlohmann::ordered_json& value : hmaV92WhitelistConfiguration["templates"][templateName]["appList"])
											{
												const std::string packageName = value.get<std::string>();
												if (!hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].contains(packageName))
													hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].push_back(packageName);
											}
											templateArrayIt = hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["applyTemplates"].erase(templateArrayIt);
										}
										else
											++templateArrayIt;
										std::sort(hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].begin(), hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end());
										if (std::find(hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].begin(), hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end(), innerEntryIt.key()) != hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end())
											hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].erase(std::remove(hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].begin(), hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end(), innerEntryIt.key()), hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end());
									}
							}
					if ("." == this->outputHmaV92WhitelistFilePath)
					{
						std:cout << hmaV92WhitelistConfiguration.dump() << std::endl;
						this->flag |= 4/* 0b00000100 */;
					}
					else if (this->handleDirectory(this->outputHmaV92WhitelistFilePath))
						try
						{
							std::ofstream outputHmaV92WhitelistFile(this->outputHmaV92WhitelistFilePath);
							if (outputHmaV92WhitelistFile.is_open())
							{
								outputHmaV92WhitelistFile << hmaV92WhitelistConfiguration.dump();
								outputHmaV92WhitelistFile.close();
								this->flag |= 4/* 0b00000100 */;
							}
							else
								this->print("Failed to open the output whitelist configuration JSON file. ", LogLevel::Error);
						}
						catch (...)
						{
							this->print("Failed to generate the output whitelist configuration JSON file. ", LogLevel::Error);
						}
					else
						this->print("Failed to handle the parent directory for the output whitelist configuration JSON file. ", LogLevel::Error);
				}
				
				/* hmaV92BlacklistConfiguration */
				if (this->outputHmaV92BlacklistFilePath.empty())
					this->flag |= 8/* 0b00001000 */;
				else
				{
					nlohmann::ordered_json hmaV92BlacklistConfiguration(hmaConfiguration);
					hmaV92BlacklistConfiguration["scope"] = nlohmann::json::object();
					for (nlohmann::json::const_iterator outerEntryIt = this->j["C"].begin(); outerEntryIt != this->j["C"].end(); ++outerEntryIt)
						for (const nlohmann::json& value : outerEntryIt.value())
						{
							const std::string packageName = value.get<std::string>();
							hmaV92BlacklistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
							hmaV92BlacklistConfiguration["scope"][packageName]["useWhitelist"] = false;
							hmaV92BlacklistConfiguration["scope"][packageName]["excludeSystemApps"] = false;
							hmaV92BlacklistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							for (nlohmann::json::const_iterator innerEntryIt = this->j["C"].begin(); innerEntryIt != this->j["C"].end(); ++innerEntryIt)
								if (innerEntryIt != outerEntryIt)
									hmaV92BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistC" + innerEntryIt.key());
							hmaV92BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistD");
							hmaV92BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistM");
							hmaV92BlacklistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						}
					for (const nlohmann::json& outerValue : this->j["D"])
					{
						const std::string outerPackageName = outerValue.get<std::string>();
						hmaV92BlacklistConfiguration["scope"][outerPackageName] = nlohmann::ordered_json::object();
						hmaV92BlacklistConfiguration["scope"][outerPackageName]["useWhitelist"] = false;
						hmaV92BlacklistConfiguration["scope"][outerPackageName]["excludeSystemApps"] = false;
						hmaV92BlacklistConfiguration["scope"][outerPackageName]["applyTemplates"] = nlohmann::ordered_json::array();
						hmaV92BlacklistConfiguration["scope"][outerPackageName]["applyTemplates"].push_back("BlacklistM");
						hmaV92BlacklistConfiguration["scope"][outerPackageName]["extraAppList"] = nlohmann::ordered_json::array();
						for (const nlohmann::json& innerValue : this->j["D"])
						{
							const std::string innerPackageName = innerValue.get<std::string>();
							if (outerPackageName != innerPackageName)
								hmaV92BlacklistConfiguration["scope"][outerPackageName]["extraAppList"].push_back(innerPackageName);
						}
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["N"].begin(); outerEntryIt != this->j["N"].end(); ++outerEntryIt)
						if (hmaV92BlacklistConfiguration["scope"].contains(outerEntryIt.key()))
							for (nlohmann::json::const_iterator innerEntryIt = outerEntryIt.value().begin(); innerEntryIt != outerEntryIt.value().end(); ++innerEntryIt)
							{
									if (innerEntryIt.value().get<bool>()) // Search for all the blacklist-type templates where the package name is located from the applied template list and unzip the templates to "extraAppList" without the package name
									for (nlohmann::ordered_json::iterator templateArrayIt = hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["applyTemplates"].begin(); templateArrayIt != hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["applyTemplates"].end(); )
									{
										const std::string templateName = templateArrayIt.value().get<std::string>();
										if (hmaV92BlacklistConfiguration["templates"].contains(templateName) && hmaV92BlacklistConfiguration["templates"][templateName].contains("isWhitelist") && hmaV92BlacklistConfiguration["templates"][templateName]["isWhitelist"].is_boolean() && !hmaV92BlacklistConfiguration["templates"][templateName]["isWhitelist"].get<bool>() && hmaV92BlacklistConfiguration["templates"][templateName].contains("appList") && hmaV92BlacklistConfiguration["templates"][templateName]["appList"].is_array() && std::find(hmaV92BlacklistConfiguration["templates"][templateName]["appList"].begin(), hmaV92BlacklistConfiguration["templates"][templateName]["appList"].end(), innerEntryIt.key()) != hmaV92BlacklistConfiguration["templates"][templateName]["appList"].end())
										{
											for (const nlohmann::ordered_json& value : hmaV92BlacklistConfiguration["templates"][templateName]["appList"])
											{
												const std::string packageName = value.get<std::string>();
												if (!hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].contains(packageName))
													hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].push_back(packageName);
											}
											templateArrayIt = hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["applyTemplates"].erase(templateArrayIt);
										}
										else
											++templateArrayIt;
										std::sort(hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].begin(), hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end());
										if (std::find(hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].begin(), hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end(), innerEntryIt.key()) != hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end())
											hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].erase(std::remove(hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].begin(), hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end(), innerEntryIt.key()), hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end());
									}
								else // add to the ``extraAppList`` if it is not in any of the templates applied
								{
									bool addingFlag = !hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].contains(innerEntryIt.key());
									if (addingFlag)
										for (const nlohmann::ordered_json& value : hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["applyTemplates"])
										{
											const std::string templateName = value.get<std::string>();
											if (hmaV92BlacklistConfiguration["templates"].contains(templateName) && hmaV92BlacklistConfiguration["templates"][templateName].contains("isWhitelist") && !hmaV92BlacklistConfiguration["templates"][templateName]["isWhitelist"].get<bool>() && hmaV92BlacklistConfiguration["templates"][templateName].contains("appList") && hmaV92BlacklistConfiguration["templates"][templateName]["appList"].contains(innerEntryIt.key()))
											{
												addingFlag = false;
												break;
											}
										}
									if (addingFlag)
										hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].push_back(innerEntryIt.key());
								}
							}
					if ("." == this->outputHmaV92BlacklistFilePath)
					{
						std:cout << hmaV92BlacklistConfiguration.dump() << std::endl;
						this->flag |= 8/* 0b00001000 */;
					}
					else if (this->handleDirectory(this->outputHmaV92BlacklistFilePath))
						try
						{
							std::ofstream outputHmaV92BlacklistFile(this->outputHmaV92BlacklistFilePath);
							if (outputHmaV92BlacklistFile.is_open())
							{
								outputHmaV92BlacklistFile << hmaV92BlacklistConfiguration.dump();
								outputHmaV92BlacklistFile.close();
								this->flag |= 8/* 0b00001000 */;
							}
							else
								this->print("Failed to open the output blacklist configuration JSON file. ", LogLevel::Error);
						}
						catch (...)
						{
							this->print("Failed to generate the output blacklist configuration JSON file. ", LogLevel::Error);
						}
					else
						this->print("Failed to handle the parent directory for the output blacklist configuration JSON file. ", LogLevel::Error);
				}
			}
			return this->flag & 8/* 0b00001000 */ && this->flag & 4/* 0b00000100 */ && this->flag & 2/* 0b00000010 */ && this->flag & 1/* 0b00000001 */;
		}
		else
		{
			this->print("Error: Please parse the input database JSON file before generating the HMA configuration JSON files. ", LogLevel::Error);
			return false;
		}
	}
	bool generateHMAOSSConfigurations() // 0b??00??11 | 0b00110000 -> 0b??11??11
	{
		if (this->flag & 2/* 0b00000010 */ && this->flag & 1/* 0b00000001 */)
		{
			this->flag &= 207/* 0b11001111 */;
			if (this->outputHmaossV93WhitelistFilePath.empty() && this->outputHmaossV93BlacklistFilePath.empty())
				this->flag |= 48/* 0b00110000 */;
			else
			{
				/* commonHMAOSSv93 */
				nlohmann::ordered_json commonHMAOSSv93{};
				commonHMAOSSv93["configVersion"] = 93;
				commonHMAOSSv93["detailLog"] = true;
				commonHMAOSSv93["errorOnlyLog"] = false;
				commonHMAOSSv93["maxLogSize"] = 1024;
				commonHMAOSSv93["forceMountData"] = true;
				commonHMAOSSv93["disableActivityLaunchProtection"] = false;
				commonHMAOSSv93["altAppDataIsolation"] = true;
				commonHMAOSSv93["altVoldAppDataIsolation"] = false;
				commonHMAOSSv93["skipSystemAppDataIsolation"] = true;
				commonHMAOSSv93["packageQueryWorkaround"] = false;
				commonHMAOSSv93["enableInternet"] = 2;
				commonHMAOSSv93["templates"] = nlohmann::ordered_json::object();
				for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
				{
					const std::string whitelistName = "WhitelistC" + entryIt.key();
					commonHMAOSSv93["templates"][whitelistName] = nlohmann::ordered_json::object();
					commonHMAOSSv93["templates"][whitelistName]["isWhitelist"] = true;
					commonHMAOSSv93["templates"][whitelistName]["appList"] = nlohmann::ordered_json::array();
					for (const nlohmann::json& value : entryIt.value())
						commonHMAOSSv93["templates"][whitelistName]["appList"].push_back(value.get<std::string>());
				}
				for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
				{
					const std::string blacklistName = "BlacklistC" + entryIt.key();
					commonHMAOSSv93["templates"][blacklistName] = nlohmann::ordered_json::object();
					commonHMAOSSv93["templates"][blacklistName]["isWhitelist"] = false;
					commonHMAOSSv93["templates"][blacklistName]["appList"] = nlohmann::ordered_json::array();
					for (const nlohmann::json& value : entryIt.value())
						commonHMAOSSv93["templates"][blacklistName]["appList"].push_back(value.get<std::string>());
				}
				commonHMAOSSv93["templates"]["BlacklistD"] = nlohmann::ordered_json::object();
				commonHMAOSSv93["templates"]["BlacklistD"]["isWhitelist"] = false;
				commonHMAOSSv93["templates"]["BlacklistD"]["appList"] = nlohmann::ordered_json::array();
				for (const nlohmann::json& value : this->j["D"])
					commonHMAOSSv93["templates"]["BlacklistD"]["appList"].push_back(value.get<std::string>());
				commonHMAOSSv93["templates"]["BlacklistM"] = nlohmann::ordered_json::object();
				commonHMAOSSv93["templates"]["BlacklistM"]["isWhitelist"] = false;
				commonHMAOSSv93["templates"]["BlacklistM"]["appList"] = nlohmann::ordered_json::array();
				for (const nlohmann::json& value : this->j["M"])
					commonHMAOSSv93["templates"]["BlacklistM"]["appList"].push_back(value.get<std::string>());
				
				/* whitelistHMAOSSv93 */
				if (this->outputHmaossV93WhitelistFilePath.empty())
					this->flag |= 16/* 0b00010000 */;
				else
				{
					nlohmann::ordered_json whitelistHMAOSSv93(commonHMAOSSv93);
					whitelistHMAOSSv93["scope"] = nlohmann::json::object();
					for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
						for (const nlohmann::json& value : entryIt.value())
						{
							const std::string packageName = value.get<std::string>();
							whitelistHMAOSSv93["scope"][packageName] = nlohmann::ordered_json::object();
							whitelistHMAOSSv93["scope"][packageName]["useWhitelist"] = true;
							whitelistHMAOSSv93["scope"][packageName]["excludeSystemApps"] = true;
							whitelistHMAOSSv93["scope"][packageName]["hideInstallationSource"] = false;
							whitelistHMAOSSv93["scope"][packageName]["hideSystemInstallationSource"] = false;
							whitelistHMAOSSv93["scope"][packageName]["excludeTargetInstallationSource"] = false;
							whitelistHMAOSSv93["scope"][packageName]["invertActivityLaunchProtection"] = false;
							whitelistHMAOSSv93["scope"][packageName]["excludeVoldIsolation"] = false;
							whitelistHMAOSSv93["scope"][packageName]["restrictedZygotePermissions"] = nlohmann::ordered_json::array();
							whitelistHMAOSSv93["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							whitelistHMAOSSv93["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
							whitelistHMAOSSv93["scope"][packageName]["applyPresets"] = nlohmann::ordered_json::array();
							whitelistHMAOSSv93["scope"][packageName]["applySettingTemplates"] = nlohmann::ordered_json::array();
							whitelistHMAOSSv93["scope"][packageName]["applySettingsPresets"] = nlohmann::ordered_json::array();
							whitelistHMAOSSv93["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
							whitelistHMAOSSv93["scope"][packageName]["extraOppositeAppList"] = nlohmann::ordered_json::array();
						}
					for (const nlohmann::json& value : this->j["D"])
					{
						const std::string packageName = value.get<std::string>();
						whitelistHMAOSSv93["scope"][packageName] = nlohmann::ordered_json::object();
						whitelistHMAOSSv93["scope"][packageName]["useWhitelist"] = true;
						whitelistHMAOSSv93["scope"][packageName]["excludeSystemApps"] = true;
						whitelistHMAOSSv93["scope"][packageName]["hideInstallationSource"] = false;
						whitelistHMAOSSv93["scope"][packageName]["hideSystemInstallationSource"] = false;
						whitelistHMAOSSv93["scope"][packageName]["excludeTargetInstallationSource"] = false;
						whitelistHMAOSSv93["scope"][packageName]["invertActivityLaunchProtection"] = false;
						whitelistHMAOSSv93["scope"][packageName]["excludeVoldIsolation"] = false;
						whitelistHMAOSSv93["scope"][packageName]["restrictedZygotePermissions"] = nlohmann::ordered_json::array();
						whitelistHMAOSSv93["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
						for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
							whitelistHMAOSSv93["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
						whitelistHMAOSSv93["scope"][packageName]["applyPresets"] = nlohmann::ordered_json::array();
						whitelistHMAOSSv93["scope"][packageName]["applySettingTemplates"] = nlohmann::ordered_json::array();
						whitelistHMAOSSv93["scope"][packageName]["applySettingsPresets"] = nlohmann::ordered_json::array();
						whitelistHMAOSSv93["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						whitelistHMAOSSv93["scope"][packageName]["extraAppList"].push_back(packageName);
						whitelistHMAOSSv93["scope"][packageName]["extraOppositeAppList"] = nlohmann::ordered_json::array();
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["N"].begin(); outerEntryIt != this->j["N"].end(); ++outerEntryIt)
						if (whitelistHMAOSSv93["scope"].contains(outerEntryIt.key()))
							for (nlohmann::json::const_iterator innerEntryIt = outerEntryIt.value().begin(); innerEntryIt != outerEntryIt.value().end(); ++innerEntryIt)
							{
								if (innerEntryIt.value().get<bool>())
								{
									whitelistHMAOSSv93["scope"][outerEntryIt.key()]["extraAppList"].push_back(innerEntryIt.key());
									std::sort(whitelistHMAOSSv93["scope"][outerEntryIt.key()]["extraAppList"].begin(), whitelistHMAOSSv93["scope"][outerEntryIt.key()]["extraAppList"].end());
								}
								else
								{
									whitelistHMAOSSv93["scope"][outerEntryIt.key()]["extraOppositeAppList"].push_back(innerEntryIt.key());
									std::sort(whitelistHMAOSSv93["scope"][outerEntryIt.key()]["extraOppositeAppList"].begin(), whitelistHMAOSSv93["scope"][outerEntryIt.key()]["extraOppositeAppList"].end());
								}
							}
					if ("." == this->outputHmaossV93WhitelistFilePath)
					{
						std::cout << whitelistHMAOSSv93.dump() << std::endl;
						this->flag |= 16/* 0b00010000 */;
					}
					else if (this->handleDirectory(this->outputHmaossV93WhitelistFilePath))
						try
						{
							std::ofstream outputHmaossV93WhitelistFile(this->outputHmaossV93WhitelistFilePath);
							if (outputHmaossV93WhitelistFile.is_open())
							{
								outputHmaossV93WhitelistFile << whitelistHMAOSSv93.dump();
								outputHmaossV93WhitelistFile.close();
								this->flag |= 16/* 0b00010000 */;
							}
							else
								this->print("Failed to open the output whitelist v93 configuration JSON file. ", LogLevel::Error);
						}
						catch (...)
						{
							this->print("Failed to generate the output whitelist v93 configuration JSON file. ", LogLevel::Error);
						}
					else
						this->print("Failed to handle the parent directory for the output whitelist v93 configuration JSON file. ", LogLevel::Error);
				}
				
				/* blacklistHMAOSSv93 */
				if (this->outputHmaossV93BlacklistFilePath.empty())
					this->flag |= 32/* 0b00100000 */;
				else
				{
					nlohmann::ordered_json blacklistHMAOSSv93(commonHMAOSSv93);
					blacklistHMAOSSv93["scope"] = nlohmann::json::object();
					for (nlohmann::json::const_iterator outerEntryIt = this->j["C"].begin(); outerEntryIt != this->j["C"].end(); ++outerEntryIt)
						for (const nlohmann::json& value : outerEntryIt.value())
						{
							const std::string packageName = value.get<std::string>();
							blacklistHMAOSSv93["scope"][packageName] = nlohmann::ordered_json::object();
							blacklistHMAOSSv93["scope"][packageName]["useWhitelist"] = false;
							blacklistHMAOSSv93["scope"][packageName]["excludeSystemApps"] = false;
							blacklistHMAOSSv93["scope"][packageName]["hideInstallationSource"] = false;
							blacklistHMAOSSv93["scope"][packageName]["hideSystemInstallationSource"] = false;
							blacklistHMAOSSv93["scope"][packageName]["excludeTargetInstallationSource"] = false;
							blacklistHMAOSSv93["scope"][packageName]["invertActivityLaunchProtection"] = false;
							blacklistHMAOSSv93["scope"][packageName]["excludeVoldIsolation"] = false;
							blacklistHMAOSSv93["scope"][packageName]["restrictedZygotePermissions"] = nlohmann::ordered_json::array();
							blacklistHMAOSSv93["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							for (nlohmann::json::const_iterator innerEntryIt = this->j["C"].begin(); innerEntryIt != this->j["C"].end(); ++innerEntryIt)
								if (innerEntryIt != outerEntryIt)
									blacklistHMAOSSv93["scope"][packageName]["applyTemplates"].push_back("BlacklistC" + innerEntryIt.key());
							blacklistHMAOSSv93["scope"][packageName]["applyTemplates"].push_back("BlacklistD");
							blacklistHMAOSSv93["scope"][packageName]["applyPresets"] = nlohmann::ordered_json::array();
							blacklistHMAOSSv93["scope"][packageName]["applySettingTemplates"] = nlohmann::ordered_json::array();
							blacklistHMAOSSv93["scope"][packageName]["applySettingsPresets"] = nlohmann::ordered_json::array();
							blacklistHMAOSSv93["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
							blacklistHMAOSSv93["scope"][packageName]["extraOppositeAppList"] = nlohmann::ordered_json::array();
						}
					for (const nlohmann::json& value : this->j["D"])
					{
						const std::string packageName = value.get<std::string>();
						blacklistHMAOSSv93["scope"][packageName] = nlohmann::ordered_json::object();
						blacklistHMAOSSv93["scope"][packageName]["useWhitelist"] = false;
						blacklistHMAOSSv93["scope"][packageName]["excludeSystemApps"] = false;
						blacklistHMAOSSv93["scope"][packageName]["hideInstallationSource"] = false;
						blacklistHMAOSSv93["scope"][packageName]["hideSystemInstallationSource"] = false;
						blacklistHMAOSSv93["scope"][packageName]["excludeTargetInstallationSource"] = false;
						blacklistHMAOSSv93["scope"][packageName]["invertActivityLaunchProtection"] = false;
						blacklistHMAOSSv93["scope"][packageName]["excludeVoldIsolation"] = false;
						blacklistHMAOSSv93["scope"][packageName]["restrictedZygotePermissions"] = nlohmann::ordered_json::array();
						blacklistHMAOSSv93["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
						blacklistHMAOSSv93["scope"][packageName]["applyTemplates"].push_back("BlacklistD");
						blacklistHMAOSSv93["scope"][packageName]["applyTemplates"].push_back("BlacklistM");
						blacklistHMAOSSv93["scope"][packageName]["applyPresets"] = nlohmann::ordered_json::array();
						blacklistHMAOSSv93["scope"][packageName]["applySettingTemplates"] = nlohmann::ordered_json::array();
						blacklistHMAOSSv93["scope"][packageName]["applySettingsPresets"] = nlohmann::ordered_json::array();
						blacklistHMAOSSv93["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						blacklistHMAOSSv93["scope"][packageName]["extraOppositeAppList"] = nlohmann::ordered_json::array();
						blacklistHMAOSSv93["scope"][packageName]["extraOppositeAppList"].push_back(packageName);
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["N"].begin(); outerEntryIt != this->j["N"].end(); ++outerEntryIt)
						if (blacklistHMAOSSv93["scope"].contains(outerEntryIt.key()))
							for (nlohmann::json::const_iterator innerEntryIt = outerEntryIt.value().begin(); innerEntryIt != outerEntryIt.value().end(); ++innerEntryIt)
							{
								if (innerEntryIt.value().get<bool>())
								{
									blacklistHMAOSSv93["scope"][outerEntryIt.key()]["extraOppositeAppList"].push_back(innerEntryIt.key());
									std::sort(blacklistHMAOSSv93["scope"][outerEntryIt.key()]["extraOppositeAppList"].begin(), blacklistHMAOSSv93["scope"][outerEntryIt.key()]["extraOppositeAppList"].end()); 
								}
								else
								{
									blacklistHMAOSSv93["scope"][outerEntryIt.key()]["extraAppList"].push_back(innerEntryIt.key());
									std::sort(blacklistHMAOSSv93["scope"][outerEntryIt.key()]["extraAppList"].begin(), blacklistHMAOSSv93["scope"][outerEntryIt.key()]["extraAppList"].end());
								}
							}
					if ("." == this->outputHmaossV93BlacklistFilePath)
					{
						std::cout << blacklistHMAOSSv93.dump() << std::endl;
						this->flag |= 32/* 0b00100000 */;
					}
					else if (this->handleDirectory(this->outputHmaossV93BlacklistFilePath))
						try
						{
							std::ofstream outputHmaossV93BlacklistFile(this->outputHmaossV93BlacklistFilePath);
							if (outputHmaossV93BlacklistFile.is_open())
							{
								outputHmaossV93BlacklistFile << blacklistHMAOSSv93.dump();
								outputHmaossV93BlacklistFile.close();
								this->flag |= 32/* 0b00100000 */;
							}
							else
								this->print("Failed to open the output blacklist configuration JSON file. ", LogLevel::Error);
						}
						catch (...)
						{
							this->print("Failed to generate the output blacklist configuration JSON file. ", LogLevel::Error);
						}
					else
						this->print("Failed to handle the parent directory for the output blacklist configuration JSON file. ", LogLevel::Error);
				}
			}
			return this->flag & 32/* 0b00100000 */ && this->flag & 16/* 0b00010000 */ && this->flag & 2/* 0b00000010 */ && this->flag & 1/* 0b00000001 */;
		}
		else
		{
			this->print("Error: Please parse the input database JSON file before generating the HMA-OSS configuration JSON files. ", LogLevel::Error);
			return false;
		}
	}
	bool generatePathTester() // 0b?0????11 | 0b01000000 -> 0b?1????11
	{
		if (this->flag & 2/* 0b00000010 */ && this->flag & 1/* 0b00000001 */)
		{
			this->flag &= 191/* 0b10111111 */;
			if (this->outputPathTesterFilePath.empty())
				this->flag |= 64/* 0b01000000 */;
			else
			{
				std::string shellScript = "#!/system/bin/sh\n";
				shellScript += "readonly EXIT_SUCCESS=0\n";
				shellScript += "readonly EXIT_FAILURE=1\n\n";
				shellScript += "readonly EOF=-1\n\n";
				shellScript += "errorLevel=${EXIT_SUCCESS}\n";
				shellScript += "if echo \"${EXTERNAL_STORAGE}\" | grep -qE \"^(/[A-Za-z0-9_-]+)+$\";\n";
				shellScript += "then\n";
				shellScript += "\treadonly directories=\"/data/data /data/user/0 /data/user_de/0 ${EXTERNAL_STORAGE}/Android/data ${EXTERNAL_STORAGE}/Android/obb ${EXTERNAL_STORAGE}/Android/\u200Bdata ${EXTERNAL_STORAGE}/Android/\u200Bobb\"\n";
				shellScript += "\treadonly wxDownloadDirectoryPath=\"${EXTERNAL_STORAGE}/Download/WechatXposed\"\n";
				shellScript += "else\n";
				shellScript += "\treadonly directories=\"/data/data /data/user/0 /data/user_de/0 /sdcard/Android/data /sdcard/Android/obb /sdcard/Android/\u200Bdata /sdcard/Android/\u200Bobb\"\n";
				shellScript += "\treadonly wxDownloadDirectoryPath=\"/sdcard/Download/WechatXposed\"\n";
				shellScript += "fi\n\n";
				shellScript += "if [[ $(id -u) -eq 0 ]];\n";
				shellScript += "then\n";
				shellScript += "\terrorLevel=${EOF}\n";
				shellScript += "\techo \"You are running this script as root. Please run it as a regular user.\"\n";
				shellScript += "\texit ${errorLevel}\n";
				shellScript += "else\n";
				shellScript += "\techo -e \"The execution of the path tester has begun. \"\n";
				shellScript += "fi\n\n";
				shellScript += "readonly D=" + this->array2string(this->j["D"], "\"", " ", "\"") + "\n";
				shellScript += "for d in ${D};\n";
				shellScript += "do\n";
				shellScript += "\tfor directory in ${directories};\n";
				shellScript += "\tdo\n";
				shellScript += "\t\tsensitivePath=\"${directory}/${d}\"\n";
				shellScript += "\t\tif [[ -e \"${sensitivePath}\" ]];\n";
				shellScript += "\t\tthen\n";
				shellScript += "\t\t\terrorLevel=${EXIT_FAILURE}\n";
				shellScript += "\t\t\techo \"- Found \\\"${sensitivePath}\\\" (\\$D\\$). \"\n";
				shellScript += "\t\tfi\n";
				shellScript += "\tdone\n";
				shellScript += "done\n\n";
				shellScript += "readonly M=" + this->array2string(this->j["M"], "\"", " ", "\"") + "\n";
				shellScript += "for m in ${M};\n";
				shellScript += "do\n";
				shellScript += "\tfor directory in ${directories};\n";
				shellScript += "\tdo\n";
				shellScript += "\t\tsensitivePath=\"${directory}/${m}\"\n";
				shellScript += "\t\tif [[ -e \"${sensitivePath}\" ]];\n";
				shellScript += "\t\tthen\n";
				shellScript += "\t\t\terrorLevel=${EXIT_FAILURE}\n";
				shellScript += "\t\t\techo \"- Found \\\"${sensitivePath}\\\" (\\$M\\$). \"\n";
				shellScript += "\t\tfi\n";
				shellScript += "\tdone\n";
				shellScript += "done\n\n";
				shellScript += "if [[ -e \"${wxDownloadDirectoryPath}\" ]];\n";
				shellScript += "then\n";
				shellScript += "\terrorLevel=${EXIT_FAILURE}\n";
				shellScript += "\techo \"- Found \\\"${wxDownloadDirectoryPath}\\\" (\\$M_P\\$). \"\n";
				shellScript += "fi\n\n";
				shellScript += "if [[ ${EXIT_SUCCESS} -eq ${errorLevel} ]];\n";
				shellScript += "then\n";
				shellScript += "\techo \"Finished scanning as a regular user. You should have bypassed the path detection.\"\n";
				shellScript += "else\n";
				shellScript += "\techo \"Finished scanning as a regular user. Your LRFP environments may have been exposed if there is one or more applications other than the one used to execute this script in the above detection results. \"\n";
				shellScript += "fi\n\n";
				shellScript += "exit ${errorLevel}\n";
				if ("." == this->outputPathTesterFilePath)
				{
					std::cout << shellScript << std::endl;
					this->flag |= 64/* 0b01000000 */;
				}
				else if (this->handleDirectory(this->outputPathTesterFilePath))
					try
					{
						std::ofstream outputPathTesterFile(this->outputPathTesterFilePath);
						if (outputPathTesterFile.is_open())
						{
							outputPathTesterFile << shellScript;
							outputPathTesterFile.close();
							this->flag |= 64/* 0b01000000 */;
						}
						else
							this->print("Failed to open the output path tester script file. ", LogLevel::Error);
					}
					catch (...)
					{
						this->print("Failed to generate the output path tester script file. ", LogLevel::Error);
					}
				else
					this->print("Failed to handle the parent directory for the output path tester script file. ", LogLevel::Error);
			}
			return this->flag & 64/* 0b01000000 */ && this->flag & 2/* 0b00000010 */ && this->flag & 1/* 0b00000001 */;
		}
		else
		{
			this->print("Please parse the input database JSON file before generating the path tester script file. ", LogLevel::Error);
			return false;
		}
	}
	bool generateTrickyStoreTarget()
	{
		if (this->flag & 2/* 0b00000010 */ && this->flag & 1/* 0b00000001 */)
		{
			this->flag &= 127/* 0b01111111 */;
			if (this->outputTrickyStoreTargetFilePath.empty())
				this->flag |= 128/* 0b10000000 */;
			else
			{
				std::set<std::string> targetPackageNames{};
				for (nlohmann::json::const_iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
					for (const nlohmann::json& value : entryIt.value())
						targetPackageNames.insert(value.get<std::string>());
				for (const nlohmann::json& value : this->j["D"])
					targetPackageNames.insert(value.get<std::string>());
				for (const nlohmann::json& value : this->j["M"])
					targetPackageNames.insert(value.get<std::string>());
				for (const nlohmann::json& value : this->j["S"])
					targetPackageNames.insert(value.get<std::string>());
				for (nlohmann::json::iterator outerEntryIt = this->j["T"].begin(); outerEntryIt != this->j["T"].end(); ++outerEntryIt)
					if (outerEntryIt.value().get<bool>())
						targetPackageNames.insert(outerEntryIt.key());
					else if (targetPackageNames.count(outerEntryIt.key()))
						targetPackageNames.erase(outerEntryIt.key());
				if ("." == this->outputTrickyStoreTargetFilePath)
				{
					for (const std::string& packageName : targetPackageNames)
						std::cout << packageName << std::endl;
					this->flag |= 128/* 0b10000000 */;
				}
				else if (this->handleDirectory(this->outputTrickyStoreTargetFilePath))
					try
					{
						std::ofstream outputTargetFile(this->outputTrickyStoreTargetFilePath);
						if (outputTargetFile.is_open())
						{
							for (const std::string& packageName : targetPackageNames)
								outputTargetFile << packageName << std::endl;
							outputTargetFile.close();
							this->flag |= 128/* 0b10000000 */;
						}
						else
							this->print("Failed to open the output Tricky Store target text file. ", LogLevel::Error);
					}
					catch (...)
					{
						this->print("Failed to generate the output Tricky Store target text file. ", LogLevel::Error);
					}
				else
					this->print("Failed to handle the parent directory for the output Tricky Store target text file. ", LogLevel::Error);
			}
			return this->flag & 128/* 0b10000000 */ && this->flag & 2/* 0b00000010 */ && this->flag & 1/* 0b00000001 */;
		}
		else
		{
			this->print("Please parse the input database JSON file before generating the Tricky Store target text file. ", LogLevel::Error);
			return false;
		}
	}
	unsigned short getFlag() const
	{
		return this->flag;
	}
};



int main(int argc, char* argv[])
{
	Generator generator{};
	bool exitFlag = false;
	const bool parsingFlag = generator.parseArguments(argc, argv, exitFlag);
	if (exitFlag)
		return EXIT_SUCCESS;
	else if (parsingFlag && generator.parseJSON() && generator.scanApplicationDirectories())
	{
		bool generationFlag = generator.generateHMAConfigurations();
		generationFlag = generator.generateHMAOSSConfigurations() && generationFlag;
		generationFlag = generator.generatePathTester() && generationFlag;
		generationFlag = generator.generateTrickyStoreTarget() && generationFlag;
		return generationFlag ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	else
		return EOF;
}