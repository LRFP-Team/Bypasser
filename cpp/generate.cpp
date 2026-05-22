#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <regex>
#include "nlohmann/json.hpp" // https://github.com/nlohmann/json
#ifndef MODULE_NAME
#define MODULE_NAME "Bypasser"
#endif
#ifndef CPP_VERSION
#define CPP_VERSION "3.8.5.5+HKT20260509000000000000000"
#endif
#ifndef REGEX_PATTERN
#define REGEX_PATTERN "^[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+$"
#endif


#pragma pack(push, 1)
struct LocalFileHeader
{
	uint32_t signature; // 0x04034b50
	uint16_t versionNeeded;
	uint16_t generalPurposeBitFlag;
	uint16_t compressionMethod;
	uint16_t lastModFileTime;
	uint16_t lastModFileDate;
	uint32_t crc32;
	uint32_t compressedSize;
	uint32_t uncompressedSize;
	uint16_t fileNameLength;
	uint16_t extraFieldLength;
};

struct CentralDirectoryFileHeader
{
	uint32_t signature; // 0x02014b50
	uint16_t versionMadeBy;
	uint16_t versionNeeded;
	uint16_t generalPurposeBitFlag;
	uint16_t compressionMethod;
	uint16_t lastModFileTime;
	uint16_t lastModFileDate;
	uint32_t crc32;
	uint32_t compressedSize;
	uint32_t uncompressedSize;
	uint16_t fileNameLength;
	uint16_t extraFieldLength;
	uint16_t fileCommentLength;
	uint16_t diskNumberStart;
	uint16_t internalFileAttributes;
	uint32_t externalFileAttributes;
	uint32_t localHeaderOffset;
};

struct EndOfCentralDirectoryRecord
{
	uint32_t signature; // 0x06054b50
	uint16_t numberOfThisDisk;
	uint16_t diskWhereCentralDirectoryStarts;
	uint16_t numberOfCentralDirectoryRecordsOnThisDisk;
	uint16_t totalNumberOfCentralDirectoryRecords;
	uint32_t sizeOfCentralDirectory;
	uint32_t offsetOfStartOfCentralDirectory;
	uint16_t commentLength;
};
#pragma pack(pop)


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
	inline static const std::string DefaultDatabaseFilePath = "database.json";
	inline static const LogLevel DefaultLevel = LogLevel::Info;
	inline static const std::vector<std::string> helpArguments{ "?", "/?", "-?", "h", "/h", "-h", "help", "/help", "--help" };
	inline static const std::vector<std::string> inputDatabaseArguments{ "i", "/i", "-i", "inputDatabase", "/inputDatabase", "--inputDatabase" };
	inline static const std::vector<std::string> logLevelArguments{ "l", "/l", "-l", "logLevel", "/logLevel", "--logLevel" };
	inline static const std::vector<std::string> outputHmaV92WhitelistArguments{ "oa92w", "/oa92w", "-oa92w", "outputHmaV92Whitelist", "/outputHmaV92Whitelist", "--outputHmaV92Whitelist" };
	inline static const std::vector<std::string> outputHmaV92BlacklistArguments{ "oa92b", "/oa92b", "-oa92b", "outputHmaV92Blacklist", "/outputHmaV92Blacklist", "--outputHmaV92Blacklist" };
	inline static const std::vector<std::string> outputHmaV93WhitelistArguments{ "oa93w", "/oa93w", "-oa93w", "outputHmaV93Whitelist", "/outputHmaV93Whitelist", "--outputHmaV93Whitelist" };
	inline static const std::vector<std::string> outputHmaV93BlacklistArguments{ "oa93b", "/oa93b", "-oa93b", "outputHmaV93Blacklist", "/outputHmaV93Blacklist", "--outputHmaV93Blacklist" };
	inline static const std::vector<std::string> outputHmaossV93WhitelistArguments{ "os93w", "/os93w", "-os93w", "outputHmaossV93Whitelist", "/outputHmaossV93Whitelist", "--outputHmaossV93Whitelist" };
	inline static const std::vector<std::string> outputHmaossV93BlacklistArguments{ "os93b", "/os93b", "-os93b", "outputHmaossV93Blacklist", "/outputHmaossV93Blacklist", "--outputHmaossV93Blacklist" };
	inline static const std::vector<std::string> outputPathTesterArguments{ "op", "/op", "-op", "outputPathTester", "/outputPathTester", "--outputPathTester" };
	inline static const std::vector<std::string> outputTrickyStoreTargetArguments{ "ot", "/ot", "-ot", "outputTrickyStoreTarget", "/outputTrickyStoreTarget", "--outputTrickyStoreTarget" };
	inline static const std::regex Pattern = std::regex(REGEX_PATTERN);
	inline static const std::vector<std::string> ApplicationPartitions{ "/data", "/product", "/system", "/system_ext", "/vendor" };
	inline static const std::vector<std::string> ApplicationDirectoryNames{ "app", "app-private", "priv-app" };
	inline static const std::string HexadecimalCharacterSet = "0123456789ABCDEF";
	inline static const std::string ReportLink = "https://github.com/LRFP-Team/Bypasser/issues";
	
	unsigned short flag = 0 /* 0b 0000 0000 0000 0000 */;
	std::string inputDatabaseFilePath = DefaultDatabaseFilePath;
	LogLevel logLevel = DefaultLevel;
	std::string outputHmaV92WhitelistFilePath{};
	std::string outputHmaV92BlacklistFilePath{};
	std::string outputHmaV93WhitelistFilePath{};
	std::string outputHmaV93BlacklistFilePath{};
	std::string outputHmaossV93WhitelistFilePath{};
	std::string outputHmaossV93BlacklistFilePath{};
	std::string outputPathTesterFilePath{};
	std::string outputTrickyStoreTargetFilePath{};
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
	std::string logLevel2string(const LogLevel level) const
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
		std::cout << "\t" << this->vector2string(helpArguments) << "\t\tPrint the help information. " << std::endl;
		std::cout << "\t" << this->vector2string(inputDatabaseArguments) << "<path>\t\tSpecify the input database JSON file path. The default value is \"" << DefaultDatabaseFilePath << "\". " << std::endl;
		std::cout << "\t" << this->vector2string(logLevelArguments) << "<level>\t\tSpecify the log level (std::cerr) from " << this->logLevel2string(LogLevel::All) << " to " << this->logLevel2string(LogLevel::Off) << ". The default value is " << this->logLevel2string(DefaultLevel) << ". " << std::endl;
		std::cout << "\t" << this->vector2string(outputHmaV92WhitelistArguments) << "<path>\t\tSpecify the output HMA v92 whitelist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(outputHmaV92BlacklistArguments) << "<path>\t\tSpecify the output HMA v92 blacklist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(outputHmaV93WhitelistArguments) << "<path>\t\tSpecify the output HMA v93 whitelist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(outputHmaV93BlacklistArguments) << "<path>\t\tSpecify the output HMA v93 blacklist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(outputHmaossV93WhitelistArguments) << "<path>\t\tSpecify the output HMA-OSS v93 whitelist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(outputHmaossV93BlacklistArguments) << "<path>\t\tSpecify the output HMA-OSS v93 blacklist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(outputPathTesterArguments) << "<path>\t\tSpecify the output path tester shell script file path. " << std::endl;
		std::cout << "\t" << this->vector2string(outputTrickyStoreTargetArguments) << "<path>\t\tSpecify the output Tricky Store target text file path. " << std::endl << std::endl;
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
				formattedMessage += "\\";
				formattedMessage += character;
				break;
			default:
				if (character <= 31 || 127 == character)
					formattedMessage += "\\x" + std::string(1, HexadecimalCharacterSet[character >> 4]) + std::string(1, HexadecimalCharacterSet[character & 15/* 0b 0000 1111 */]);
				else
					formattedMessage += character;
				break;
			}
		formattedMessage += "\"";
		return formattedMessage;
	}
	bool checkoutApplication(const std::string& apkFilePath, bool& isPlugin)
	{
		std::ifstream apkFile(apkFilePath, std::ios::binary | std::ios::ate);
		if (apkFile.is_open())
		{
			const std::streampos fileSize = apkFile.tellg();
			if (0 == fileSize)
				return false;
			else
			{
				/* Seek the EOCD signature (0x06054b50) whose minimum size is 32 bytes from the end of the file */
				const size_t maxSearch = (fileSize > static_cast<std::streampos>(65557)) ? 65557 : static_cast<size_t>(fileSize);
				std::vector<char> buffer(maxSearch);
				apkFile.seekg(fileSize - static_cast<std::streampos>(maxSearch));
				apkFile.read(buffer.data(), maxSearch);
				long long int eocdOffset = EOF;
				for (long long int i = static_cast<long long int>(maxSearch) - 22; i >= 0; --i)
				{
					uint32_t signature;
					std::memcpy(&signature, &buffer[i], sizeof(signature));
					if (0x06054b50 == signature)
					{
						eocdOffset = i;
						break;
					}
				}
				if (EOF == eocdOffset) // broken ZIP signature
					return false;
				else
				{
					/* Walk the ZIP */
					EndOfCentralDirectoryRecord eocd;
					std::memcpy(&eocd, &buffer[eocdOffset], sizeof(EndOfCentralDirectoryRecord));
					apkFile.seekg(eocd.offsetOfStartOfCentralDirectory);
					for (uint16_t i = 0; i < eocd.totalNumberOfCentralDirectoryRecords; ++i)
					{
						CentralDirectoryFileHeader cdfh;
						apkFile.read(reinterpret_cast<char*>(&cdfh), sizeof(CentralDirectoryFileHeader));
						if (0x02014b50 == cdfh.signature)
						{
							std::vector<char> nameBuf(cdfh.fileNameLength);
							apkFile.read(nameBuf.data(), cdfh.fileNameLength);
							std::string fileName(nameBuf.data(), cdfh.fileNameLength);
							if ("assets/xposed_init" == fileName)
							{
								isPlugin = cdfh.uncompressedSize > 0;
								this->print(std::string("Located ") + (isPlugin ? "true" : "false") + " \"assets/xposed_init\" in " + this->formatMessage(apkFilePath) + ". ", LogLevel::Trace);
								return true;
							}
							apkFile.seekg(cdfh.extraFieldLength + cdfh.fileCommentLength, std::ios::cur);
						}
						else // broken item signature
							return false;
					}
					isPlugin = false;
					return true;
				}
			}
		}
		else
			return false;
	}
	bool binarySearch(const nlohmann::json& array, const std::string& x, size_t& insertionIndex) const
	{
		if (array.is_array())
		{
			size_t low = 0, high = array.size(); // [low, high)
			while (low < high)
			{
				size_t mid = low + ((high - low) >> 1);
				const std::string& midValue = array[mid].get<std::string>();
				if (x == midValue)
				{
					insertionIndex = mid;
					return true;
				}
				else if (midValue < x)
					low = mid + 1;
				else
					high = mid;
			}
			insertionIndex = low;
			return false;
		}
		else
			return false;
	}
	bool addToDatabase(const std::string& packageName, const bool isPlugin, size_t& unrecordedPluginCount, size_t& unrecordedNonPluginCount)
	{
		size_t insertionIndex = static_cast<size_t>(EOF);
		if (isPlugin)
		{
			if (!this->binarySearch(this->j["M"], packageName, insertionIndex) && insertionIndex != static_cast<size_t>(EOF))
			{
				this->j["M"].insert(this->j["M"].begin() + insertionIndex, packageName);
				++unrecordedPluginCount;
				return true;
			}
		}
		else
		{
			bool notInDatabase = !this->binarySearch(this->j["C"][""], packageName, insertionIndex) && !this->binarySearch(this->j["D"], packageName, insertionIndex) && !this->binarySearch(this->j["M"], packageName, insertionIndex) && !this->binarySearch(this->j["S"], packageName, insertionIndex);
			if (notInDatabase)
				for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
					if ("L" != entryIt.key() && entryIt.value().is_array() && this->binarySearch(entryIt.value(), packageName, insertionIndex))
					{
						notInDatabase = false;
						break;
					}
			if (notInDatabase && !this->binarySearch(this->j["C"]["_"]["L"], packageName, insertionIndex) && insertionIndex != static_cast<size_t>(EOF))
			{
				this->j["C"]["_"]["L"].insert(this->j["C"]["_"]["L"].begin() + insertionIndex, packageName);
				++unrecordedNonPluginCount;
				return true;
			}
		}
		return false;
	}
	bool traverseApplicationDirectory(const std::filesystem::path& directoryPath, size_t& unrecordedPluginCount, size_t& unrecordedNonPluginCount)
	{
		if (!std::filesystem::is_symlink(directoryPath) && std::filesystem::is_directory(directoryPath))
			try
			{
				/**
				 * formCount = directoryFormCount + fileFormCount + invalidFormCount
				 * directoryFormCount = dataDirectoryFormCount + nonDataDirectoryFormCount + invalidDirectoryFormCount + failureInstallationCount
				 * dataDirectoryFormCount = dataDirectoryFormSuccessCount + dataDirectoryFormFailureCount
				 * nonDataDirectoryFormCount = nonDataDirectoryFormSuccessCount + nonDataDirectoryFormFailureCount
				 * failureInstallationCount = failureInstallationRemovedCount + failureInstallationUnremovedCount
				 * fileFormCount = validFileFormCount + invalidFileFormCount
				 * validFileFormCount = validFileFormSuccessCount + validFileFormFailureCount
				 */
				size_t formCount = 0, directoryFormCount = 0, dataDirectoryFormCount = 0, dataDirectoryFormSuccessCount = 0, dataDirectoryFormFailureCount = 0, nonDataDirectoryFormCount = 0, nonDataDirectoryFormSuccessCount = 0, nonDataDirectoryFormFailureCount = 0, invalidDirectoryFormCount = 0, failureInstallationCount = 0, failureInstallationRemovedCount = 0, failureInstallationUnremovedCount = 0, fileFormCount = 0, validFileFormCount = 0, validFileFormSuccessCount = 0, validFileFormFailureCount = 0, invalidFileFormCount = 0, invalidFormCount = 0;
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
						else if (26 == directoryNameLength && '~' == directoryName[0] && '~' == directoryName[1] && '=' == directoryName[24] && '=' == directoryName[25])
						{
							/* Analyze the application installed under ``/data`` */
							bool isValid = true;
							for (size_t i = 2; i < 24 && isValid; ++i)
								if (!(('A' <= directoryName[i] && directoryName[i] <= 'Z') || ('a' <= directoryName[i] && directoryName[i] <= 'z') || ('0' <= directoryName[i] && directoryName[i] <= '9') || '_' == directoryName[i] || '-' == directoryName[i])) // no '.' here
									isValid = false;
							if (isValid)
							{
								/* Enter the second-layer directory */
								this->print("Trying to enter the second-layer directory for " + this->formatMessage(firstLayerEntry.path().string()) + ". ", LogLevel::Trace);
								std::filesystem::directory_entry secondLayerEntry{};
								for (std::filesystem::directory_iterator directoryIt = std::filesystem::directory_iterator(firstLayerEntry.path()); directoryIt != std::filesystem::directory_iterator(); ++directoryIt)
									if (!directoryIt->is_symlink() && directoryIt->is_directory())
										if (secondLayerEntry.path().empty())
											secondLayerEntry = *directoryIt;
										else
										{
											isValid = false;
											break;
										}
									else
									{
										isValid = false;
										break;
									}
								if (isValid)
								{
									this->print("Entered the second-layer directory " + this->formatMessage(secondLayerEntry.path().string()) + ". ", LogLevel::Trace);
									std::string packageName = secondLayerEntry.path().filename().string();
									const size_t position = packageName.find('-');
									size_t packageNameLength = packageName.length();
									if (std::string::npos != position && position + 3 <= packageNameLength && '=' == packageName[--packageNameLength] && '=' == packageName[--packageNameLength])
									{
										for (size_t i = 0; i < packageNameLength; ++i)
											if (!(('A' <= packageName[i] && packageName[i] <= 'Z') || ('a' <= packageName[i] && packageName[i] <= 'z') || ('0' <= packageName[i] && packageName[i] <= '9') || '_' == packageName[i] || '.' == packageName[i] || '-' == packageName[i]))
											{
												isValid = false;
												break;
											}
										if (isValid)
										{
											packageName = packageName.substr(0, position);
											this->print("Located the package name " + this->formatMessage(packageName) + " in the second-layer directory " + this->formatMessage(secondLayerEntry.path().string()) + ". ", LogLevel::Trace);
											if (std::regex_match(packageName, Pattern))
											{
												/* Enter the third-layer directory */
												this->print("Trying to enter the third-layer directory for " + this->formatMessage(secondLayerEntry.path().string()) + ". ", LogLevel::Trace);
												std::filesystem::directory_entry thirdLayerEntry{};
												for (std::filesystem::directory_iterator directoryIt = std::filesystem::directory_iterator(secondLayerEntry.path()); directoryIt != std::filesystem::directory_iterator(); ++directoryIt)
												{
													if (directoryIt->is_symlink())
													{
														isValid = false;
														break;
													}
													else if (directoryIt->is_directory())
													{
														if ("lib" != directoryIt->path().filename().string() && "oat" != directoryIt->path().filename().string())
														{
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
														isValid = false;
														break;
													}
												}
												if (isValid && !thirdLayerEntry.path().empty())
												{
													this->print("Entered the third-layer directory " + this->formatMessage(thirdLayerEntry.path().string()) + ". ", LogLevel::Trace);
													++dataDirectoryFormCount;
													bool isPlugin = false;
													if (this->checkoutApplication(thirdLayerEntry.path().string(), isPlugin))
													{
														++dataDirectoryFormSuccessCount;
														this->addToDatabase(packageName, isPlugin, unrecordedPluginCount, unrecordedNonPluginCount);
													}
													else
														++dataDirectoryFormFailureCount;
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
							else
								++invalidDirectoryFormCount;
						}
						else
						{
							/* Analyze the application installed under the partitions other than ``/data`` */
							bool isValid = true;
							for (size_t i = 0; i < directoryNameLength && isValid; ++i)
								if (!(('A' <= directoryName[i] && directoryName[i] <= 'Z') || ('a' <= directoryName[i] && directoryName[i] <= 'z') || ('0' <= directoryName[i] && directoryName[i] <= '9') || '_' == directoryName[i] || '.' == directoryName[i] || '-' == directoryName[i]))
									isValid = false;
							if (isValid)
							{
								this->print("Trying to enter the second-layer directory for " + this->formatMessage(firstLayerEntry.path().string()) + ". ", LogLevel::Trace);
								std::filesystem::path apkFilePathObject = firstLayerEntry.path();
								apkFilePathObject /= directoryName + ".apk";
								if (!std::filesystem::is_symlink(apkFilePathObject) && std::filesystem::is_regular_file(apkFilePathObject))
								{
									this->print("Entered the second-layer directory " + this->formatMessage(apkFilePathObject.string()) + ". ", LogLevel::Trace);
									++nonDataDirectoryFormCount;
									bool isPlugin = false;
									if (this->checkoutApplication(apkFilePathObject.string(), isPlugin))
									{
										++nonDataDirectoryFormSuccessCount;
										//this->addToDatabase(packageName, isPlugin, unrecordedPluginCount, unrecordedNonPluginCount);
									}
									else
										++nonDataDirectoryFormFailureCount;
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
						std::string packageName = firstLayerEntry.path().stem().string();
						size_t position = packageName.find('-');
						if (std::string::npos != position)
							packageName = packageName.substr(0, position);
						if (std::regex_match(packageName, Pattern))
						{
							++validFileFormCount;
							bool isPlugin = false;
							if (this->checkoutApplication(firstLayerEntry.path().string(), isPlugin))
							{
								++validFileFormSuccessCount;
								this->addToDatabase(packageName, isPlugin, unrecordedPluginCount, unrecordedNonPluginCount);
							}
							else
								++validFileFormFailureCount;
						}
						else
							++invalidFileFormCount;
					}
					else
						++invalidFormCount;
				}
				this->print("Finished traversing " + this->formatMessage(directoryPath.string()) + " with " + std::to_string(formCount) + "{" + std::to_string(directoryFormCount) + "[" + std::to_string(dataDirectoryFormCount) + "(" + std::to_string(dataDirectoryFormSuccessCount) + " + " + std::to_string(dataDirectoryFormFailureCount) + ") + " + std::to_string(nonDataDirectoryFormCount) + "(" + std::to_string(nonDataDirectoryFormSuccessCount) + " + " + std::to_string(nonDataDirectoryFormFailureCount) + ") + " + std::to_string(invalidDirectoryFormCount) + " + " + std::to_string(failureInstallationCount) + "(" + std::to_string(failureInstallationRemovedCount) + " + " + std::to_string(failureInstallationUnremovedCount) + ")] + " + std::to_string(fileFormCount) + "[" + std::to_string(validFileFormCount) + "(" + std::to_string(validFileFormSuccessCount) + " + " + std::to_string(validFileFormFailureCount) + ") + " + std::to_string(invalidFileFormCount) + "]" + " + " + std::to_string(invalidFormCount) + "} processed. ", LogLevel::Debug);
				return true;
			}
			catch (...)
			{
				this->print("Failed to traverse " + this->formatMessage(directoryPath.string()) + ". ", LogLevel::Warning);
				return false;
			}
		else
			return false;
	}
	bool checkInputFlags() const
	{
		return this->flag & 128/* 0b 0000 0000 1000 0000 */ && this->flag & 64/* 0b 0000 0000 0100 0000 */ && this->flag & 32/* 0b 0000 0000 0010 0000 */ && this->flag & 16/* 0b 0000 0000 0001 0000 */ && this->flag & 8/* 0b 0000 0000 0000 1000 */ && this->flag & 4/* 0b 0000 0000 0000 0100 */ && this->flag & 2/* 0b 0000 0000 0000 0010 */ && this->flag & 1/* 0b 0000 0000 0000 0001 */;
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
		for (nlohmann::json::const_iterator arrayIt = elements.cbegin(); arrayIt != elements.cend(); ++arrayIt)
			if (arrayIt->is_string())
			{
				s += arrayIt->get<std::string>();
				for (++arrayIt; arrayIt != elements.cend(); ++arrayIt)
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
			this->inputDatabaseFilePath = DefaultDatabaseFilePath;
			this->logLevel = DefaultLevel;
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
			if (std::find(helpArguments.cbegin(), helpArguments.cend(), argv[i]) != helpArguments.cend())
			{
				this->printHelp();
				exitFlag = true;
				return true;
			}
			else if (std::find(inputDatabaseArguments.cbegin(), inputDatabaseArguments.cend(), argv[i]) != inputDatabaseArguments.cend())
				if (++i < argc)
					this->inputDatabaseFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(logLevelArguments.cbegin(), logLevelArguments.cend(), argv[i]) != logLevelArguments.cend())
				if (++i < argc)
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
						break;
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
					{
						const unsigned char lowerBound = static_cast<unsigned char>(LogLevel::All), upperBound = static_cast<unsigned char>(LogLevel::Off);
						if constexpr (/*0 <= lowerBound && */lowerBound <= upperBound && upperBound <= 9)
						{
							const unsigned char x = argv[i][0] >= '0' ? static_cast<unsigned char>(argv[i][0]) - '0' : static_cast<unsigned char>(argv[i][0]);
							if (lowerBound <= x && x <= upperBound)
								this->logLevel = static_cast<LogLevel>(x);
							else
								this->print("The passed log level cannot be recognized, which has been skipped. ", LogLevel::Warning);
						}
						else
							this->print("The passed log level cannot be recognized, which has been skipped. ", LogLevel::Warning);
						break;
					}
					}
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaV92WhitelistArguments.cbegin(), outputHmaV92WhitelistArguments.cend(), argv[i]) != outputHmaV92WhitelistArguments.cend())
				if (++i < argc)
					this->outputHmaV92WhitelistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaV92BlacklistArguments.cbegin(), outputHmaV92BlacklistArguments.cend(), argv[i]) != outputHmaV92BlacklistArguments.cend())
				if (++i < argc)
					this->outputHmaV92BlacklistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaV93WhitelistArguments.cbegin(), outputHmaV93WhitelistArguments.cend(), argv[i]) != outputHmaV93WhitelistArguments.cend())
				if (++i < argc)
					this->outputHmaV93WhitelistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaV93BlacklistArguments.cbegin(), outputHmaV93BlacklistArguments.cend(), argv[i]) != outputHmaV93BlacklistArguments.cend())
				if (++i < argc)
					this->outputHmaV93BlacklistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaossV93WhitelistArguments.cbegin(), outputHmaossV93WhitelistArguments.cend(), argv[i]) != outputHmaossV93WhitelistArguments.cend())
				if (++i < argc)
					this->outputHmaossV93WhitelistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputHmaossV93BlacklistArguments.cbegin(), outputHmaossV93BlacklistArguments.cend(), argv[i]) != outputHmaossV93BlacklistArguments.cend())
				if (++i < argc)
					this->outputHmaossV93BlacklistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputPathTesterArguments.cbegin(), outputPathTesterArguments.cend(), argv[i]) != outputPathTesterArguments.cend())
				if (++i < argc)
					this->outputPathTesterFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputTrickyStoreTargetArguments.cbegin(), outputTrickyStoreTargetArguments.cend(), argv[i]) != outputTrickyStoreTargetArguments.cend())
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
	bool parseArguments(int argc, char* argv[], bool& exitFlag) { return this->parseArguments(argc, argv, exitFlag, true); } // 0b 0000 0000 0000 0000 | 0b 0000 0000 0000 0001 -> 0b 0000 0000 0000 0001
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
						size_t removedKeyCount = 0;
						for (nlohmann::json::iterator entryIt = this->j.begin(); entryIt != this->j.end(); )
							if (std::find(keysToKeep.cbegin(), keysToKeep.cend(), entryIt.key()) != keysToKeep.cend())
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
							this->print("This program expects the version " + cppVersion + " while the input database is not, which may result in warnings. ", LogLevel::Warning);
						
						/* Second-level */
						removedKeyCount = 0;
						if (this->j.contains("C") && this->j["C"].is_object())
						{
							size_t removedValueCount = 0;
							if (this->j["C"].contains("") && this->j["C"][""].is_array())
								for (nlohmann::json::iterator arrayIt = this->j["C"][""].begin(); arrayIt != this->j["C"][""].end(); )
									if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), Pattern))
										++arrayIt;
									else
									{
										arrayIt = this->j["C"][""].erase(arrayIt);
										++removedValueCount;
									}
							else
								this->j["C"][""] = nlohmann::json::array();
							if (this->j["C"].contains("_") && this->j["C"]["_"].is_object())
								for (nlohmann::json::iterator entryIt = this->j["C"]["_"].begin(); entryIt != this->j["C"]["_"].end(); )
									if (entryIt.key().length() == 1 && 'A' <= entryIt.key()[0] && entryIt.key()[0] <= 'Z' && entryIt.value().is_array())
									{
										for (nlohmann::json::iterator arrayIt = entryIt.value().begin(); arrayIt != entryIt.value().end(); )
											if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), Pattern))
												++arrayIt;
											else
											{
												arrayIt = entryIt.value().erase(arrayIt);
												++removedValueCount;
											}
										++entryIt;
									}
									else
									{
										entryIt = this->j["C"]["_"].erase(entryIt);
										++removedKeyCount;
									}
							else
								this->j["C"]["_"] = nlohmann::json::object();
							for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); )
								if ("" == entryIt.key() || "_" == entryIt.key())
									++entryIt;
								else if ("*" == entryIt.key())
								{
									/* Compatible with $C^*$ */
									for (const nlohmann::json& value : entryIt.value())
										if (value.is_string() && std::regex_match(value.get<std::string>(), Pattern))
											this->j["C"][""][entryIt.key()].push_back(value.get<std::string>());
										else
											++removedValueCount;
									entryIt = this->j["C"].erase(entryIt);
								}
								else if (entryIt.key().length() == 1 && 'A' <= entryIt.key()[0] && entryIt.key()[0] <= 'Z' && entryIt.value().is_array())
								{
									/* Compatible with Version 3.6.x ($C_X$) */
									if (!this->j["C"]["_"].contains(entryIt.key()))
										this->j["C"]["_"][entryIt.key()] = nlohmann::json::array();
									for (const nlohmann::json& value : entryIt.value())
										if (value.is_string() && std::regex_match(value.get<std::string>(), Pattern))
											this->j["C"]["_"][entryIt.key()].push_back(value.get<std::string>());
										else
											++removedValueCount;
									entryIt = this->j["C"].erase(entryIt);
								}
								else if (std::regex_match(entryIt.key(), Pattern)/* && entryIt.value().is_null() */)
								{
									/* Compatible with Version 3.6.x ($C$) */
									this->j["C"][""].push_back(entryIt.key());
									entryIt = this->j["C"].erase(entryIt);
								}
								else
								{
									entryIt = this->j["C"].erase(entryIt);
									++removedKeyCount;
								}
							std::sort(this->j["C"][""].begin(), this->j["C"][""].end());
							this->j["C"][""].erase(std::unique(this->j["C"][""].begin(), this->j["C"][""].end()), this->j["C"][""].end());
							for (nlohmann::json::iterator entryIt = this->j["C"]["_"].begin(); entryIt != this->j["C"]["_"].end(); )
								if (this->j["C"]["_"][entryIt.key()].empty()) // different from Python
									entryIt = this->j["C"]["_"].erase(entryIt);
								else
								{
									std::sort(this->j["C"]["_"][entryIt.key()].begin(), this->j["C"]["_"][entryIt.key()].end());
									this->j["C"]["_"][entryIt.key()].erase(std::unique(this->j["C"]["_"][entryIt.key()].begin(), this->j["C"]["_"][entryIt.key()].end()), this->j["C"]["_"][entryIt.key()].end());
									++entryIt;
								}
							if (1 == removedKeyCount)
								this->print("A key in $C$ and its descendants is invalid, which has been removed. ", LogLevel::Warning);
							else if (removedKeyCount)
								this->print(std::to_string(removedKeyCount) + " keys in $C$ and its descendants are invalid, which have been removed. ", LogLevel::Warning);
							if (1 == removedValueCount)
								this->print("A value in $C$ and its descendants is invalid, which has been removed. ", LogLevel::Warning);
							else if (removedValueCount)
								this->print(std::to_string(removedValueCount) + " values in $C$ and its descendants are invalid, which have been removed. ", LogLevel::Warning);
						}
						else
						{
							this->j["C"] = nlohmann::json::object();
							this->j["C"][""] = nlohmann::json::array();
							this->j["C"]["_"] = nlohmann::json::object();
							this->print("Initialized $C$ as an empty dictionary. ", LogLevel::Warning);
						}
						if (this->j.contains("D") && this->j["D"].is_array())
						{
							int removedValueCount = 0;
							for (nlohmann::json::iterator arrayIt = this->j["D"].begin(); arrayIt != this->j["D"].end(); )
								if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), Pattern))
									++arrayIt;
								else
								{
									arrayIt = this->j["D"].erase(arrayIt);
									++removedValueCount;
								}
							std::sort(this->j["D"].begin(), this->j["D"].end());
							this->j["D"].erase(std::unique(this->j["D"].begin(), this->j["D"].end()), this->j["D"].end());
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
								if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), Pattern))
									++arrayIt;
								else
								{
									arrayIt = this->j["M"].erase(arrayIt);
									++removedValueCount;
								}
							std::sort(this->j["M"].begin(), this->j["M"].end());
							this->j["M"].erase(std::unique(this->j["M"].begin(), this->j["M"].end()), this->j["M"].end());
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
								if (std::regex_match(outerEntryIt.key(), Pattern) && outerEntryIt.value().is_object())
								{
									int removedEntryCount = 0;
									for (nlohmann::json::iterator innerEntryIt = outerEntryIt.value().begin(); innerEntryIt != outerEntryIt.value().end(); )
										if (std::regex_match(innerEntryIt.key(), Pattern) && innerEntryIt.value().is_boolean())
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
								if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), Pattern))
									++arrayIt;
								else
								{
									arrayIt = this->j["S"].erase(arrayIt);
									++removedValueCount;
								}
							std::sort(this->j["S"].begin(), this->j["S"].end());
							this->j["S"].erase(std::unique(this->j["S"].begin(), this->j["S"].end()), this->j["S"].end());
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
								if (std::regex_match(entryIt.key(), Pattern) && entryIt.value().is_boolean())
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
			this->print("Please parse the command-line arguments before parsing the input database JSON file. ", LogLevel::Error);
			return false;
		}
	}
	bool scanApplicationDirectories() // 0b 0000 0000 0000 0011 | 0b 0000 0000 1111 1100 -> 0b 0000 0000 1111 1111
	{
		if (this->flag & 2/* 0b 0000 0000 0000 0010 */ && this->flag & 1/* 0b 0000 0000 0000 0001 */)
		{
			this->flag &= 3/* 0b 0000 0000 0000 0011 */;
			const size_t applicationPartitionCount = std::min(ApplicationPartitions.size(), static_cast<size_t>(6));
			if (!(this->j["C"]["_"].contains("L") && this->j["C"]["_"]["L"].is_array()))
				this->j["C"]["_"]["L"] = nlohmann::json::array();
			size_t unrecordedPluginCount = 0, unrecordedNonPluginCount = 0;
			for (size_t i = 0; i < applicationPartitionCount; ++i)
			{
				bool localFlag = true;
				for (const std::string& applicationDirectoryName : ApplicationDirectoryNames)
				{
					std::filesystem::path applicationDirectoryPath = ApplicationPartitions[i];
					applicationDirectoryPath /= applicationDirectoryName;
					if (!std::filesystem::is_symlink(applicationDirectoryPath) && std::filesystem::is_directory(applicationDirectoryPath) && !this->traverseApplicationDirectory(applicationDirectoryPath, unrecordedPluginCount, unrecordedNonPluginCount))
						localFlag = false;
				}
				if (localFlag)
					this->flag |= 1 << (i + 2)/* 0b 0000 0000 (?)??? ??00 */;
			}
			if (unrecordedPluginCount || unrecordedNonPluginCount)
				this->print("Found " + std::to_string(unrecordedPluginCount) + " unrecorded plugin(s) ($M$) and " + std::to_string(unrecordedNonPluginCount) + " unrecorded plain application(s) ($C$, $D$, or $M$). You are invited to report the generated configurations to " + ReportLink, LogLevel::Info);
			if (this->j["C"]["_"]["L"].empty())
				this->j["C"]["_"].erase("L");
			const size_t effectiveHighestBit = applicationPartitionCount + 2, highestBit = 8;
			bool localFlag = applicationPartitionCount >= 1;
			size_t index = 2;
			for (; index < effectiveHighestBit; ++index)
				if (!((this->flag >> index) & 1/* 0b 0000 0000 0000 0001 */))
				{
					localFlag = false;
					break;
				}
			if (localFlag)
				for (; index < highestBit; ++index)
					this->flag |= 1 << index/* 0b 0000 0000 ???? ??00 */;
			return this->checkInputFlags();
		}
		else
		{
			this->print("Please parse the input database JSON file before scanning application directories. ", LogLevel::Error);
			return false;
		}
	}
	bool generateHMAConfigurations() // 0b ???? 0000 1111 1111 | 0b 0000 1111 0000 0000 -> 0b ???? 1111 1111 1111
	{
		if (this->checkInputFlags())
		{
			if (this->outputHmaV92WhitelistFilePath.empty() && this->outputHmaV92BlacklistFilePath.empty() && this->outputHmaV93WhitelistFilePath.empty() && this->outputHmaV93BlacklistFilePath.empty())
				this->flag |= 3840/* 0b 0000 1111 0000 0000 */;
			else
			{
				this->flag &= 61695/* 0b 1111 0000 1111 1111 */;
				
				/* hmaConfiguration */
				nlohmann::ordered_json hmaConfiguration{};
				hmaConfiguration["configVersion"] = 92;
				hmaConfiguration["detailLog"] = true;
				hmaConfiguration["maxLogSize"] = 1024;
				hmaConfiguration["forceMountData"] = true;
				hmaConfiguration["aggressiveFilter"] = true;
				hmaConfiguration["templates"] = nlohmann::ordered_json::object();
				hmaConfiguration["templates"]["WhitelistC"] = nlohmann::ordered_json::object();
				hmaConfiguration["templates"]["WhitelistC"]["isWhitelist"] = true;
				hmaConfiguration["templates"]["WhitelistC"]["appList"] = nlohmann::ordered_json::array();
				for (const nlohmann::json& value : this->j["C"][""])
					hmaConfiguration["templates"]["WhitelistC"]["appList"].push_back(value.get<std::string>());
				for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
				{
					const std::string whitelistName = "WhitelistC" + entryIt.key();
					hmaConfiguration["templates"][whitelistName] = nlohmann::ordered_json::object();
					hmaConfiguration["templates"][whitelistName]["isWhitelist"] = true;
					hmaConfiguration["templates"][whitelistName]["appList"] = nlohmann::ordered_json::array();
					for (const nlohmann::json& value : entryIt.value())
						hmaConfiguration["templates"][whitelistName]["appList"].push_back(value.get<std::string>());
				}
				for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
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
				if (this->outputHmaV92WhitelistFilePath.empty() && this->outputHmaV93WhitelistFilePath.empty())
					this->flag |= 1280/* 0b 0000 0101 0000 0000 */;
				else
				{
					nlohmann::ordered_json hmaV92WhitelistConfiguration(hmaConfiguration);
					hmaV92WhitelistConfiguration["scope"] = nlohmann::json::object();
					for (const nlohmann::json& value : this->j["C"][""])
					{
						const std::string packageName = value.get<std::string>();
						hmaV92WhitelistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
						hmaV92WhitelistConfiguration["scope"][packageName]["useWhitelist"] = true;
						hmaV92WhitelistConfiguration["scope"][packageName]["excludeSystemApps"] = true;
						hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
						hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC");
						for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
							hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
						hmaV92WhitelistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
					}
					for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
						for (const nlohmann::json& value : entryIt.value())
						{
							const std::string packageName = value.get<std::string>();
							hmaV92WhitelistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
							hmaV92WhitelistConfiguration["scope"][packageName]["useWhitelist"] = true;
							hmaV92WhitelistConfiguration["scope"][packageName]["excludeSystemApps"] = true;
							hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC");
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
						hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC");
						for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
							hmaV92WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
						hmaV92WhitelistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						hmaV92WhitelistConfiguration["scope"][packageName]["extraAppList"].push_back(packageName);
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["N"].cbegin(); outerEntryIt != this->j["N"].cend(); ++outerEntryIt)
						if (hmaV92WhitelistConfiguration["scope"].contains(outerEntryIt.key()))
							for (nlohmann::json::const_iterator innerEntryIt = outerEntryIt.value().cbegin(); innerEntryIt != outerEntryIt.value().cend(); ++innerEntryIt)
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
										if (hmaV92WhitelistConfiguration["templates"].contains(templateName) && hmaV92WhitelistConfiguration["templates"][templateName].contains("isWhitelist") && hmaV92WhitelistConfiguration["templates"][templateName]["isWhitelist"].is_boolean() && hmaV92WhitelistConfiguration["templates"][templateName]["isWhitelist"].get<bool>() && hmaV92WhitelistConfiguration["templates"][templateName].contains("appList") && hmaV92WhitelistConfiguration["templates"][templateName]["appList"].is_array() && std::find(hmaV92WhitelistConfiguration["templates"][templateName]["appList"].cbegin(), hmaV92WhitelistConfiguration["templates"][templateName]["appList"].cend(), innerEntryIt.key()) != hmaV92WhitelistConfiguration["templates"][templateName]["appList"].cend())
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
										if (std::find(hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].cbegin(), hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].cend(), innerEntryIt.key()) != hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].cend())
											hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].erase(std::remove(hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].begin(), hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end(), innerEntryIt.key()), hmaV92WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end());
									}
							}
					if (this->outputHmaV92WhitelistFilePath.empty())
						this->flag |= 256/* 0b 0000 0001 0000 0000 */;
					else if ("." == this->outputHmaV92WhitelistFilePath)
					{
						std::cout << hmaV92WhitelistConfiguration.dump() << std::endl;
						this->flag |= 256/* 0b 0000 0001 0000 0000 */;
					}
					else if (this->handleDirectory(this->outputHmaV92WhitelistFilePath))
						try
						{
							std::ofstream outputHmaV92WhitelistFile(this->outputHmaV92WhitelistFilePath);
							if (outputHmaV92WhitelistFile.is_open())
							{
								outputHmaV92WhitelistFile << hmaV92WhitelistConfiguration.dump();
								outputHmaV92WhitelistFile.close();
								this->flag |= 256/* 0b 0000 0001 0000 0000 */;
							}
							else
								this->print("Failed to open the output HMA v92 whitelist configuration JSON file. ", LogLevel::Error);
						}
						catch (...)
						{
							this->print("Failed to generate the output HMA v92 whitelist configuration JSON file. ", LogLevel::Error);
						}
					else
						this->print("Failed to handle the parent directory for the output HMA v92 whitelist configuration JSON file. ", LogLevel::Error);
					
					/* hmaV93WhitelistConfiguration */
					if (this->outputHmaV93WhitelistFilePath.empty())
						this->flag |= 1024/* 0b 0000 0100 0000 0000 */;
					else
					{
						nlohmann::ordered_json hmaV93WhitelistConfiguration(hmaV92WhitelistConfiguration);
						hmaV93WhitelistConfiguration["configVersion"] = 93;
						for (nlohmann::ordered_json::const_iterator outerEntryIt = hmaV93WhitelistConfiguration["scope"].cbegin(); outerEntryIt != hmaV93WhitelistConfiguration["scope"].cend(); ++outerEntryIt)
							if (outerEntryIt.value().is_object())
							{
								nlohmann::ordered_json value(outerEntryIt.value());
								hmaV93WhitelistConfiguration["scope"][outerEntryIt.key()] = nlohmann::ordered_json::object();
								hmaV93WhitelistConfiguration["scope"][outerEntryIt.key()]["aggressiveFilter"] = true;
								for (nlohmann::ordered_json::const_iterator innerEntryIt = value.cbegin(); innerEntryIt != value.cend(); ++innerEntryIt)
									hmaV93WhitelistConfiguration["scope"][outerEntryIt.key()][innerEntryIt.key()] = innerEntryIt.value();
							}
						if ("." == this->outputHmaV93WhitelistFilePath)
						{
							std::cout << hmaV93WhitelistConfiguration.dump() << std::endl;
							this->flag |= 1024/* 0b 0000 0100 0000 0000 */;
						}
						else if (this->handleDirectory(this->outputHmaV93WhitelistFilePath))
							try
							{
								std::ofstream outputHmaV93WhitelistFile(this->outputHmaV93WhitelistFilePath);
								if (outputHmaV93WhitelistFile.is_open())
								{
									outputHmaV93WhitelistFile << hmaV93WhitelistConfiguration.dump();
									outputHmaV93WhitelistFile.close();
									this->flag |= 1024/* 0b 0000 0100 0000 0000 */;
								}
								else
									this->print("Failed to open the output HMA v93 whitelist configuration JSON file. ", LogLevel::Error);
							}
							catch (...)
							{
								this->print("Failed to generate the output HMA v93 whitelist configuration JSON file. ", LogLevel::Error);
							}
						else
							this->print("Failed to handle the parent directory for the output HMA v93 whitelist configuration JSON file. ", LogLevel::Error);
					}
				}
				
				/* hmaV92BlacklistConfiguration */
				if (this->outputHmaV92BlacklistFilePath.empty() && this->outputHmaV93BlacklistFilePath.empty())
					this->flag |= 2560/* 0b 0000 1010 0000 0000 */;
				else
				{
					nlohmann::ordered_json hmaV92BlacklistConfiguration(hmaConfiguration);
					hmaV92BlacklistConfiguration["scope"] = nlohmann::json::object();
					for (const nlohmann::json& value : this->j["C"][""])
					{
						const std::string packageName = value.get<std::string>();
						hmaV92BlacklistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
						hmaV92BlacklistConfiguration["scope"][packageName]["useWhitelist"] = false;
						hmaV92BlacklistConfiguration["scope"][packageName]["excludeSystemApps"] = false;
						hmaV92BlacklistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
						hmaV92BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistD");
						hmaV92BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistM");
						hmaV92BlacklistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["C"]["_"].cbegin(); outerEntryIt != this->j["C"]["_"].cend(); ++outerEntryIt)
						for (const nlohmann::json& value : outerEntryIt.value())
						{
							const std::string packageName = value.get<std::string>();
							hmaV92BlacklistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
							hmaV92BlacklistConfiguration["scope"][packageName]["useWhitelist"] = false;
							hmaV92BlacklistConfiguration["scope"][packageName]["excludeSystemApps"] = false;
							hmaV92BlacklistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							for (nlohmann::json::const_iterator innerEntryIt = this->j["C"]["_"].cbegin(); innerEntryIt != this->j["C"]["_"].cend(); ++innerEntryIt)
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
					for (nlohmann::json::const_iterator outerEntryIt = this->j["N"].cbegin(); outerEntryIt != this->j["N"].cend(); ++outerEntryIt)
						if (hmaV92BlacklistConfiguration["scope"].contains(outerEntryIt.key()))
							for (nlohmann::json::const_iterator innerEntryIt = outerEntryIt.value().cbegin(); innerEntryIt != outerEntryIt.value().cend(); ++innerEntryIt)
							{
								if (innerEntryIt.value().get<bool>()) // Search for all the blacklist-type templates where the package name is located from the applied template list and unzip the templates to "extraAppList" without the package name
									for (nlohmann::ordered_json::iterator templateArrayIt = hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["applyTemplates"].begin(); templateArrayIt != hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["applyTemplates"].end(); )
									{
										const std::string templateName = templateArrayIt.value().get<std::string>();
										if (hmaV92BlacklistConfiguration["templates"].contains(templateName) && hmaV92BlacklistConfiguration["templates"][templateName].contains("isWhitelist") && hmaV92BlacklistConfiguration["templates"][templateName]["isWhitelist"].is_boolean() && !hmaV92BlacklistConfiguration["templates"][templateName]["isWhitelist"].get<bool>() && hmaV92BlacklistConfiguration["templates"][templateName].contains("appList") && hmaV92BlacklistConfiguration["templates"][templateName]["appList"].is_array() && std::find(hmaV92BlacklistConfiguration["templates"][templateName]["appList"].cbegin(), hmaV92BlacklistConfiguration["templates"][templateName]["appList"].cend(), innerEntryIt.key()) != hmaV92BlacklistConfiguration["templates"][templateName]["appList"].cend())
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
										if (std::find(hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].cbegin(), hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].cend(), innerEntryIt.key()) != hmaV92BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].cend())
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
					if (this->outputHmaV92BlacklistFilePath.empty())
						this->flag |= 512/* 0b 0000 0010 0000 0000 */;
					else if ("." == this->outputHmaV92BlacklistFilePath)
					{
						std::cout << hmaV92BlacklistConfiguration.dump() << std::endl;
						this->flag |= 512/* 0b 0000 0010 0000 0000 */;
					}
					else if (this->handleDirectory(this->outputHmaV92BlacklistFilePath))
						try
						{
							std::ofstream outputHmaV92BlacklistFile(this->outputHmaV92BlacklistFilePath);
							if (outputHmaV92BlacklistFile.is_open())
							{
								outputHmaV92BlacklistFile << hmaV92BlacklistConfiguration.dump();
								outputHmaV92BlacklistFile.close();
								this->flag |= 512/* 0b 0000 0010 0000 0000 */;
							}
							else
								this->print("Failed to open the output HMA v92 blacklist configuration JSON file. ", LogLevel::Error);
						}
						catch (...)
						{
							this->print("Failed to generate the output HMA v92 blacklist configuration JSON file. ", LogLevel::Error);
						}
					else
						this->print("Failed to handle the parent directory for the output HMA v92 blacklist configuration JSON file. ", LogLevel::Error);
					
					/* hmaV93BlacklistConfiguration */
					if (this->outputHmaV93BlacklistFilePath.empty())
						this->flag |= 2048/* 0b 0000 1000 0000 0000 */;
					else
					{
						nlohmann::ordered_json hmaV93BlacklistConfiguration(hmaV92BlacklistConfiguration);
						hmaV93BlacklistConfiguration["configVersion"] = 93;
						for (nlohmann::ordered_json::const_iterator outerEntryIt = hmaV93BlacklistConfiguration["scope"].cbegin(); outerEntryIt != hmaV93BlacklistConfiguration["scope"].cend(); ++outerEntryIt)
							if (outerEntryIt.value().is_object())
							{
								nlohmann::ordered_json value(outerEntryIt.value());
								hmaV93BlacklistConfiguration["scope"][outerEntryIt.key()] = nlohmann::ordered_json::object();
								hmaV93BlacklistConfiguration["scope"][outerEntryIt.key()]["aggressiveFilter"] = true;
								for (nlohmann::ordered_json::const_iterator innerEntryIt = value.cbegin(); innerEntryIt != value.cend(); ++innerEntryIt)
									hmaV93BlacklistConfiguration["scope"][outerEntryIt.key()][innerEntryIt.key()] = innerEntryIt.value();
							}
						if ("." == this->outputHmaV93BlacklistFilePath)
						{
							std::cout << hmaV93BlacklistConfiguration.dump() << std::endl;
							this->flag |= 2048/* 0b 0000 1000 0000 0000 */;
						}
						else if (this->handleDirectory(this->outputHmaV93BlacklistFilePath))
							try
							{
								std::ofstream outputHmaV93BlacklistFile(this->outputHmaV93BlacklistFilePath);
								if (outputHmaV93BlacklistFile.is_open())
								{
									outputHmaV93BlacklistFile << hmaV93BlacklistConfiguration.dump();
									outputHmaV93BlacklistFile.close();
									this->flag |= 2048/* 0b 0000 1000 0000 0000 */;
								}
								else
									this->print("Failed to open the output HMA v93 blacklist configuration JSON file. ", LogLevel::Error);
							}
							catch (...)
							{
								this->print("Failed to generate the output HMA v93 blacklist configuration JSON file. ", LogLevel::Error);
							}
						else
							this->print("Failed to handle the parent directory for the output HMA v93 blacklist configuration JSON file. ", LogLevel::Error);
					}
				}
			}
			return this->flag & 2048/* 0b 0000 1000 0000 0000 */ && this->flag & 1024/* 0b 0000 0100 0000 0000 */ && this->flag & 512/* 0b 0000 0010 0000 0000 */ && this->flag & 256/* 0b 0000 0001 0000 0000 */ && this->checkInputFlags();
		}
		else
		{
			this->print("Error: Please parse the input database JSON file and conduct the local scanning before generating the HMA configuration JSON files. ", LogLevel::Error);
			return false;
		}
	}
	bool generateHMAOSSConfigurations() // 0b ??00 ???? 1111 1111 | 0b 0011 0000 0000 0000 -> 0b ??11 ???? 1111 1111
	{
		if (this->checkInputFlags())
		{
			if (this->outputHmaossV93WhitelistFilePath.empty() && this->outputHmaossV93BlacklistFilePath.empty())
				this->flag |= 12288/* 0b 0011 0000 0000 0000 */;
			else
			{
				this->flag &= 53247/* 0b 1100 1111 1111 1111 */;
				
				/* hmaossConfiguration */
				nlohmann::ordered_json hmaossConfiguration{};
				hmaossConfiguration["configVersion"] = 93;
				hmaossConfiguration["detailLog"] = true;
				hmaossConfiguration["errorOnlyLog"] = false;
				hmaossConfiguration["maxLogSize"] = 1024;
				hmaossConfiguration["forceMountData"] = true;
				hmaossConfiguration["disableActivityLaunchProtection"] = false;
				hmaossConfiguration["altAppDataIsolation"] = true;
				hmaossConfiguration["altVoldAppDataIsolation"] = false;
				hmaossConfiguration["skipSystemAppDataIsolation"] = true;
				hmaossConfiguration["packageQueryWorkaround"] = false;
				hmaossConfiguration["enableInternet"] = 2;
				hmaossConfiguration["templates"] = nlohmann::ordered_json::object();
				hmaossConfiguration["templates"]["WhitelistC"] = nlohmann::ordered_json::object();
				hmaossConfiguration["templates"]["WhitelistC"]["isWhitelist"] = true;
				hmaossConfiguration["templates"]["WhitelistC"]["appList"] = nlohmann::ordered_json::array();
				for (const nlohmann::json& value : this->j["C"][""])
					hmaossConfiguration["templates"]["WhitelistC"]["appList"].push_back(value.get<std::string>());
				for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
				{
					const std::string whitelistName = "WhitelistC" + entryIt.key();
					hmaossConfiguration["templates"][whitelistName] = nlohmann::ordered_json::object();
					hmaossConfiguration["templates"][whitelistName]["isWhitelist"] = true;
					hmaossConfiguration["templates"][whitelistName]["appList"] = nlohmann::ordered_json::array();
					for (const nlohmann::json& value : entryIt.value())
						hmaossConfiguration["templates"][whitelistName]["appList"].push_back(value.get<std::string>());
				}
				for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
				{
					const std::string blacklistName = "BlacklistC" + entryIt.key();
					hmaossConfiguration["templates"][blacklistName] = nlohmann::ordered_json::object();
					hmaossConfiguration["templates"][blacklistName]["isWhitelist"] = false;
					hmaossConfiguration["templates"][blacklistName]["appList"] = nlohmann::ordered_json::array();
					for (const nlohmann::json& value : entryIt.value())
						hmaossConfiguration["templates"][blacklistName]["appList"].push_back(value.get<std::string>());
				}
				hmaossConfiguration["templates"]["BlacklistD"] = nlohmann::ordered_json::object();
				hmaossConfiguration["templates"]["BlacklistD"]["isWhitelist"] = false;
				hmaossConfiguration["templates"]["BlacklistD"]["appList"] = nlohmann::ordered_json::array();
				for (const nlohmann::json& value : this->j["D"])
					hmaossConfiguration["templates"]["BlacklistD"]["appList"].push_back(value.get<std::string>());
				hmaossConfiguration["templates"]["BlacklistM"] = nlohmann::ordered_json::object();
				hmaossConfiguration["templates"]["BlacklistM"]["isWhitelist"] = false;
				hmaossConfiguration["templates"]["BlacklistM"]["appList"] = nlohmann::ordered_json::array();
				for (const nlohmann::json& value : this->j["M"])
					hmaossConfiguration["templates"]["BlacklistM"]["appList"].push_back(value.get<std::string>());
				
				/* hmaossV93WhitelistConfiguration */
				if (this->outputHmaossV93WhitelistFilePath.empty())
					this->flag |= 4096/* 0b 0001 0000 0000 0000 */;
				else
				{
					nlohmann::ordered_json hmaossV93WhitelistConfiguration(hmaossConfiguration);
					hmaossV93WhitelistConfiguration["scope"] = nlohmann::json::object();
					for (const nlohmann::json& value : this->j["C"][""])
					{
						const std::string packageName = value.get<std::string>();
						hmaossV93WhitelistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
						hmaossV93WhitelistConfiguration["scope"][packageName]["useWhitelist"] = true;
						hmaossV93WhitelistConfiguration["scope"][packageName]["excludeSystemApps"] = true;
						hmaossV93WhitelistConfiguration["scope"][packageName]["hideInstallationSource"] = false;
						hmaossV93WhitelistConfiguration["scope"][packageName]["hideSystemInstallationSource"] = false;
						hmaossV93WhitelistConfiguration["scope"][packageName]["excludeTargetInstallationSource"] = false;
						hmaossV93WhitelistConfiguration["scope"][packageName]["invertActivityLaunchProtection"] = false;
						hmaossV93WhitelistConfiguration["scope"][packageName]["excludeVoldIsolation"] = false;
						hmaossV93WhitelistConfiguration["scope"][packageName]["restrictedZygotePermissions"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC");
						for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
							hmaossV93WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
						hmaossV93WhitelistConfiguration["scope"][packageName]["applyPresets"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["applySettingTemplates"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["applySettingsPresets"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["extraOppositeAppList"] = nlohmann::ordered_json::array();
					}
					for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
						for (const nlohmann::json& value : entryIt.value())
						{
							const std::string packageName = value.get<std::string>();
							hmaossV93WhitelistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
							hmaossV93WhitelistConfiguration["scope"][packageName]["useWhitelist"] = true;
							hmaossV93WhitelistConfiguration["scope"][packageName]["excludeSystemApps"] = true;
							hmaossV93WhitelistConfiguration["scope"][packageName]["hideInstallationSource"] = false;
							hmaossV93WhitelistConfiguration["scope"][packageName]["hideSystemInstallationSource"] = false;
							hmaossV93WhitelistConfiguration["scope"][packageName]["excludeTargetInstallationSource"] = false;
							hmaossV93WhitelistConfiguration["scope"][packageName]["invertActivityLaunchProtection"] = false;
							hmaossV93WhitelistConfiguration["scope"][packageName]["excludeVoldIsolation"] = false;
							hmaossV93WhitelistConfiguration["scope"][packageName]["restrictedZygotePermissions"] = nlohmann::ordered_json::array();
							hmaossV93WhitelistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							hmaossV93WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC");
							hmaossV93WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
							hmaossV93WhitelistConfiguration["scope"][packageName]["applyPresets"] = nlohmann::ordered_json::array();
							hmaossV93WhitelistConfiguration["scope"][packageName]["applySettingTemplates"] = nlohmann::ordered_json::array();
							hmaossV93WhitelistConfiguration["scope"][packageName]["applySettingsPresets"] = nlohmann::ordered_json::array();
							hmaossV93WhitelistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
							hmaossV93WhitelistConfiguration["scope"][packageName]["extraOppositeAppList"] = nlohmann::ordered_json::array();
						}
					for (const nlohmann::json& value : this->j["D"])
					{
						const std::string packageName = value.get<std::string>();
						hmaossV93WhitelistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
						hmaossV93WhitelistConfiguration["scope"][packageName]["useWhitelist"] = true;
						hmaossV93WhitelistConfiguration["scope"][packageName]["excludeSystemApps"] = true;
						hmaossV93WhitelistConfiguration["scope"][packageName]["hideInstallationSource"] = false;
						hmaossV93WhitelistConfiguration["scope"][packageName]["hideSystemInstallationSource"] = false;
						hmaossV93WhitelistConfiguration["scope"][packageName]["excludeTargetInstallationSource"] = false;
						hmaossV93WhitelistConfiguration["scope"][packageName]["invertActivityLaunchProtection"] = false;
						hmaossV93WhitelistConfiguration["scope"][packageName]["excludeVoldIsolation"] = false;
						hmaossV93WhitelistConfiguration["scope"][packageName]["restrictedZygotePermissions"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC");
						for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
							hmaossV93WhitelistConfiguration["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
						hmaossV93WhitelistConfiguration["scope"][packageName]["applyPresets"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["applySettingTemplates"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["applySettingsPresets"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						hmaossV93WhitelistConfiguration["scope"][packageName]["extraAppList"].push_back(packageName);
						hmaossV93WhitelistConfiguration["scope"][packageName]["extraOppositeAppList"] = nlohmann::ordered_json::array();
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["N"].cbegin(); outerEntryIt != this->j["N"].cend(); ++outerEntryIt)
						if (hmaossV93WhitelistConfiguration["scope"].contains(outerEntryIt.key()))
							for (nlohmann::json::const_iterator innerEntryIt = outerEntryIt.value().cbegin(); innerEntryIt != outerEntryIt.value().cend(); ++innerEntryIt)
							{
								if (innerEntryIt.value().get<bool>())
								{
									hmaossV93WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].push_back(innerEntryIt.key());
									std::sort(hmaossV93WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].begin(), hmaossV93WhitelistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end());
								}
								else
								{
									hmaossV93WhitelistConfiguration["scope"][outerEntryIt.key()]["extraOppositeAppList"].push_back(innerEntryIt.key());
									std::sort(hmaossV93WhitelistConfiguration["scope"][outerEntryIt.key()]["extraOppositeAppList"].begin(), hmaossV93WhitelistConfiguration["scope"][outerEntryIt.key()]["extraOppositeAppList"].end());
								}
							}
					if ("." == this->outputHmaossV93WhitelistFilePath)
					{
						std::cout << hmaossV93WhitelistConfiguration.dump() << std::endl;
						this->flag |= 4096/* 0b 0001 0000 0000 0000 */;
					}
					else if (this->handleDirectory(this->outputHmaossV93WhitelistFilePath))
						try
						{
							std::ofstream outputHmaossV93WhitelistFile(this->outputHmaossV93WhitelistFilePath);
							if (outputHmaossV93WhitelistFile.is_open())
							{
								outputHmaossV93WhitelistFile << hmaossV93WhitelistConfiguration.dump();
								outputHmaossV93WhitelistFile.close();
								this->flag |= 4096/* 0b 0001 0000 0000 0000 */;
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
				
				/* hmaossV93BlacklistConfiguration */
				if (this->outputHmaossV93BlacklistFilePath.empty())
					this->flag |= 8192/* 0b 0010 0000 0000 0000 */;
				else
				{
					nlohmann::ordered_json hmaossV93BlacklistConfiguration(hmaossConfiguration);
					hmaossV93BlacklistConfiguration["scope"] = nlohmann::json::object();
					for (const nlohmann::json& value : this->j["C"][""])
					{
						const std::string packageName = value.get<std::string>();
						hmaossV93BlacklistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
						hmaossV93BlacklistConfiguration["scope"][packageName]["useWhitelist"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["excludeSystemApps"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["hideInstallationSource"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["hideSystemInstallationSource"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["excludeTargetInstallationSource"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["invertActivityLaunchProtection"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["excludeVoldIsolation"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["restrictedZygotePermissions"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistD");
						hmaossV93BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistM");
						hmaossV93BlacklistConfiguration["scope"][packageName]["applyPresets"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["applySettingTemplates"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["applySettingsPresets"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["extraOppositeAppList"] = nlohmann::ordered_json::array();
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["C"]["_"].cbegin(); outerEntryIt != this->j["C"]["_"].cend(); ++outerEntryIt)
						for (const nlohmann::json& value : outerEntryIt.value())
						{
							const std::string packageName = value.get<std::string>();
							hmaossV93BlacklistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
							hmaossV93BlacklistConfiguration["scope"][packageName]["useWhitelist"] = false;
							hmaossV93BlacklistConfiguration["scope"][packageName]["excludeSystemApps"] = false;
							hmaossV93BlacklistConfiguration["scope"][packageName]["hideInstallationSource"] = false;
							hmaossV93BlacklistConfiguration["scope"][packageName]["hideSystemInstallationSource"] = false;
							hmaossV93BlacklistConfiguration["scope"][packageName]["excludeTargetInstallationSource"] = false;
							hmaossV93BlacklistConfiguration["scope"][packageName]["invertActivityLaunchProtection"] = false;
							hmaossV93BlacklistConfiguration["scope"][packageName]["excludeVoldIsolation"] = false;
							hmaossV93BlacklistConfiguration["scope"][packageName]["restrictedZygotePermissions"] = nlohmann::ordered_json::array();
							hmaossV93BlacklistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							for (nlohmann::json::const_iterator innerEntryIt = this->j["C"]["_"].cbegin(); innerEntryIt != this->j["C"]["_"].cend(); ++innerEntryIt)
								if (innerEntryIt != outerEntryIt)
									hmaossV93BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistC" + innerEntryIt.key());
							hmaossV93BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistD");
							hmaossV93BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistM");
							hmaossV93BlacklistConfiguration["scope"][packageName]["applyPresets"] = nlohmann::ordered_json::array();
							hmaossV93BlacklistConfiguration["scope"][packageName]["applySettingTemplates"] = nlohmann::ordered_json::array();
							hmaossV93BlacklistConfiguration["scope"][packageName]["applySettingsPresets"] = nlohmann::ordered_json::array();
							hmaossV93BlacklistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
							hmaossV93BlacklistConfiguration["scope"][packageName]["extraOppositeAppList"] = nlohmann::ordered_json::array();
						}
					for (const nlohmann::json& value : this->j["D"])
					{
						const std::string packageName = value.get<std::string>();
						hmaossV93BlacklistConfiguration["scope"][packageName] = nlohmann::ordered_json::object();
						hmaossV93BlacklistConfiguration["scope"][packageName]["useWhitelist"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["excludeSystemApps"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["hideInstallationSource"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["hideSystemInstallationSource"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["excludeTargetInstallationSource"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["invertActivityLaunchProtection"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["excludeVoldIsolation"] = false;
						hmaossV93BlacklistConfiguration["scope"][packageName]["restrictedZygotePermissions"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistD");
						hmaossV93BlacklistConfiguration["scope"][packageName]["applyTemplates"].push_back("BlacklistM");
						hmaossV93BlacklistConfiguration["scope"][packageName]["applyPresets"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["applySettingTemplates"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["applySettingsPresets"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["extraOppositeAppList"] = nlohmann::ordered_json::array();
						hmaossV93BlacklistConfiguration["scope"][packageName]["extraOppositeAppList"].push_back(packageName);
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["N"].cbegin(); outerEntryIt != this->j["N"].cend(); ++outerEntryIt)
						if (hmaossV93BlacklistConfiguration["scope"].contains(outerEntryIt.key()))
							for (nlohmann::json::const_iterator innerEntryIt = outerEntryIt.value().cbegin(); innerEntryIt != outerEntryIt.value().cend(); ++innerEntryIt)
							{
								if (innerEntryIt.value().get<bool>())
								{
									hmaossV93BlacklistConfiguration["scope"][outerEntryIt.key()]["extraOppositeAppList"].push_back(innerEntryIt.key());
									std::sort(hmaossV93BlacklistConfiguration["scope"][outerEntryIt.key()]["extraOppositeAppList"].begin(), hmaossV93BlacklistConfiguration["scope"][outerEntryIt.key()]["extraOppositeAppList"].end()); 
								}
								else
								{
									hmaossV93BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].push_back(innerEntryIt.key());
									std::sort(hmaossV93BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].begin(), hmaossV93BlacklistConfiguration["scope"][outerEntryIt.key()]["extraAppList"].end());
								}
							}
					if ("." == this->outputHmaossV93BlacklistFilePath)
					{
						std::cout << hmaossV93BlacklistConfiguration.dump() << std::endl;
						this->flag |= 8192/* 0b 0010 0000 0000 0000 */;
					}
					else if (this->handleDirectory(this->outputHmaossV93BlacklistFilePath))
						try
						{
							std::ofstream outputHmaossV93BlacklistFile(this->outputHmaossV93BlacklistFilePath);
							if (outputHmaossV93BlacklistFile.is_open())
							{
								outputHmaossV93BlacklistFile << hmaossV93BlacklistConfiguration.dump();
								outputHmaossV93BlacklistFile.close();
								this->flag |= 8192/* 0b 0010 0000 0000 0000 */;
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
			return this->flag & 8192/* 0b 0010 0000 0000 0000 */ && this->flag & 4096 /* 0b 0001 0000 0000 0000 */ && this->checkInputFlags();
		}
		else
		{
			this->print("Error: Please parse the input database JSON file and conduct the local scanning before generating the HMA-OSS configuration JSON files. ", LogLevel::Error);
			return false;
		}
	}
	bool generatePathTester() // 0b ?0?? ???? 1111 1111 | 0b 0100 0000 0000 0000 -> 0b ?1?? ???? 1111 1111
	{
		if (this->checkInputFlags())
		{
			if (this->outputPathTesterFilePath.empty())
				this->flag |= 16384 /* 0b 0100 0000 0000 0000 */;
			else
			{
				this->flag &= 49151/* 0b 1011 1111 1111 1111 */;
				std::string shellScript = "#!/system/bin/sh\n"
				"readonly EXIT_SUCCESS=0\n"
				"readonly EXIT_FAILURE=1\n\n"
				"readonly EOF=-1\n\n"
				"errorLevel=${EXIT_SUCCESS}\n"
				"if echo \"${EXTERNAL_STORAGE}\" | grep -qE \"^(/[A-Za-z0-9_-]+)+$\";\n"
				"then\n"
				"\treadonly directories=\"/data/data /data/user/0 /data/user_de/0 ${EXTERNAL_STORAGE}/Android/data ${EXTERNAL_STORAGE}/Android/obb ${EXTERNAL_STORAGE}/Android/\u200Bdata ${EXTERNAL_STORAGE}/Android/\u200Bobb\"\n"
				"\treadonly wxDownloadDirectoryPath=\"${EXTERNAL_STORAGE}/Download/WechatXposed\"\n"
				"else\n"
				"\treadonly directories=\"/data/data /data/user/0 /data/user_de/0 /sdcard/Android/data /sdcard/Android/obb /sdcard/Android/\u200Bdata /sdcard/Android/\u200Bobb\"\n"
				"\treadonly wxDownloadDirectoryPath=\"/sdcard/Download/WechatXposed\"\n"
				"fi\n\n"
				"if [[ $(id -u) -eq 0 ]];\n"
				"then\n"
				"\terrorLevel=${EOF}\n"
				"\techo \"You are running this script as root. Please run it as a regular user.\"\n"
				"\texit ${errorLevel}\n"
				"else\n"
				"\techo -e \"The execution of the path tester has begun. \"\n"
				"fi\n\n";
				shellScript += "readonly D=" + this->array2string(this->j["D"], "\"", " ", "\"") + "\n";
				shellScript += "for d in ${D};\n"
				"do\n"
				"\tfor directory in ${directories};\n"
				"\tdo\n"
				"\t\tsensitivePath=\"${directory}/${d}\"\n"
				"\t\tif [[ -e \"${sensitivePath}\" ]];\n"
				"\t\tthen\n"
				"\t\t\terrorLevel=${EXIT_FAILURE}\n"
				"\t\t\techo \"- Found \\\"${sensitivePath}\\\" (\\$D\\$). \"\n"
				"\t\tfi\n"
				"\tdone\n"
				"done\n\n";
				shellScript += "readonly M=" + this->array2string(this->j["M"], "\"", " ", "\"") + "\n";
				shellScript += "for m in ${M};\n"
				"do\n"
				"\tfor directory in ${directories};\n"
				"\tdo\n"
				"\t\tsensitivePath=\"${directory}/${m}\"\n"
				"\t\tif [[ -e \"${sensitivePath}\" ]];\n"
				"\t\tthen\n"
				"\t\t\terrorLevel=${EXIT_FAILURE}\n"
				"\t\t\techo \"- Found \\\"${sensitivePath}\\\" (\\$M\\$). \"\n"
				"\t\tfi\n"
				"\tdone\n"
				"done\n\n"
				"if [[ -e \"${wxDownloadDirectoryPath}\" ]];\n"
				"then\n"
				"\terrorLevel=${EXIT_FAILURE}\n"
				"\techo \"- Found \\\"${wxDownloadDirectoryPath}\\\" (\\$M_P\\$). \"\n"
				"fi\n\n"
				"if [[ ${EXIT_SUCCESS} -eq ${errorLevel} ]];\n"
				"then\n"
				"\techo \"Finished scanning as a regular user. You should have bypassed the path detection.\"\n"
				"else\n"
				"\techo \"Finished scanning as a regular user. Your LRFP environments may have been exposed if there is one or more applications other than the one used to execute this script in the above detection results. \"\n"
				"fi\n\n"
				"exit ${errorLevel}\n";
				if ("." == this->outputPathTesterFilePath)
				{
					std::cout << shellScript << std::endl;
					this->flag |= 16384 /* 0b 0100 0000 0000 0000 */;
				}
				else if (this->handleDirectory(this->outputPathTesterFilePath))
					try
					{
						std::ofstream outputPathTesterFile(this->outputPathTesterFilePath);
						if (outputPathTesterFile.is_open())
						{
							outputPathTesterFile << shellScript;
							outputPathTesterFile.close();
							this->flag |= 16384 /* 0b 0100 0000 0000 0000 */;
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
			return this->flag & 16384 /* 0b 0100 0000 0000 0000 */ && this->checkInputFlags();
		}
		else
		{
			this->print("Please parse the input database JSON file and conduct the local scanning before generating the path tester script file. ", LogLevel::Error);
			return false;
		}
	}
	bool generateTrickyStoreTarget() // 0b 0??? ???? 1111 1111 | 0b 1000 0000 0000 0000 -> 0b 1??? ???? 1111 1111
	{
		if (this->checkInputFlags())
		{
			if (this->outputTrickyStoreTargetFilePath.empty())
				this->flag |= 32768/* 0b 1000 0000 0000 0000 */;
			else
			{
				this->flag &= 32767/* 0b 0111 1111 1111 1111 */;
				std::vector<std::string> targetPackageNames{};
				for (const nlohmann::json& value : this->j["C"][""])
					targetPackageNames.push_back(value.get<std::string>());
				for (nlohmann::json::const_iterator entryIt = this->j["C"]["_"].cbegin(); entryIt != this->j["C"]["_"].cend(); ++entryIt)
					for (const nlohmann::json& value : entryIt.value())
						targetPackageNames.push_back(value.get<std::string>());
				for (const nlohmann::json& value : this->j["D"])
					targetPackageNames.push_back(value.get<std::string>());
				for (const nlohmann::json& value : this->j["M"])
					targetPackageNames.push_back(value.get<std::string>());
				for (const nlohmann::json& value : this->j["S"])
					targetPackageNames.push_back(value.get<std::string>());
				for (nlohmann::json::const_iterator entryIt = this->j["T"].cbegin(); entryIt != this->j["T"].cend(); ++entryIt)
					if (entryIt.value().get<bool>())
						targetPackageNames.push_back(entryIt.key());
				std::sort(targetPackageNames.begin(), targetPackageNames.end());
				targetPackageNames.erase(std::unique(targetPackageNames.begin(), targetPackageNames.end()), targetPackageNames.end());
				for (nlohmann::json::const_iterator entryIt = this->j["T"].cbegin(); entryIt != this->j["T"].cend(); ++entryIt)
					if (!entryIt.value().get<bool>())
					{
						const std::vector<std::string>::iterator position = std::find(targetPackageNames.begin(), targetPackageNames.end(), entryIt.key());
						if (targetPackageNames.end() != position)
							targetPackageNames.erase(position);
					}
				if ("." == this->outputTrickyStoreTargetFilePath)
				{
					for (const std::string& packageName : targetPackageNames)
						std::cout << packageName << std::endl;
					this->flag |= 32768/* 0b 1000 0000 0000 0000 */;
				}
				else if (this->handleDirectory(this->outputTrickyStoreTargetFilePath))
					try
					{
						std::ofstream outputTrickyStoreTargetFile(this->outputTrickyStoreTargetFilePath);
						if (outputTrickyStoreTargetFile.is_open())
						{
							for (const std::string& packageName : targetPackageNames)
								outputTrickyStoreTargetFile << packageName << std::endl;
							outputTrickyStoreTargetFile.close();
							this->flag |= 32768/* 0b 1000 0000 0000 0000 */;
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
			return this->flag & 32768/* 0b 1000 0000 0000 0000 */ && this->checkInputFlags();
		}
		else
		{
			this->print("Please parse the input database JSON file and conduct the local scanning before generating the Tricky Store target text file. ", LogLevel::Error);
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