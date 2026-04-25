#include <iostream>
#include <filesystem>
#include <sstream>
#include <fstream>
#include <vector>
#include <set>
#include <regex>
#include "nlohmann/json.hpp"
#ifndef DATABASE_JSON
#define DATABASE_JSON "database.json"
#endif
#ifndef MODULE_NAME
#define MODULE_NAME "Bypasser"
#endif
#ifndef CPP_VERSION
#define CPP_VERSION "3.6.3"
#endif
#ifndef REGEX_PATTERN
#define REGEX_PATTERN "^[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+$"
#endif


class Generator
{
private:
	unsigned char flag = 0;
	std::string inputFilePath = DATABASE_JSON;
	std::string outputWhitelistFilePath{};
	std::string outputBlacklistFilePath{};
	std::string outputPathTesterFilePath{};
	std::string outputTargetFilePath{};
	const std::vector<std::string> helpArguments{ "h", "/h", "-h", "help", "/help", "--help" };
	const std::vector<std::string> inputArguments{ "i", "/i", "-i", "input", "/input", "--input" };
	const std::vector<std::string> outputWhitelistArguments{ "ow", "/ow", "-ow", "outputWhitelist", "/outputWhitelist", "--outputWhitelist" };
	const std::vector<std::string> outputBlacklistArguments{ "ob", "/ob", "-ob", "outputBlacklist", "/outputBlacklist", "--outputBlacklist" };
	const std::vector<std::string> outputPathTesterArguments{ "op", "/op", "-op", "outputPathTester", "/outputPathTester", "--outputPathTester" };
	const std::vector<std::string> outputTargetArguments{ "ot", "/ot", "-ot", "outputTarget", "/outputTarget", "--outputTarget" };
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
	std::string vector2string(const std::vector<std::string>& arguments) const
	{
		return this->vector2string(arguments, "[", "|", "]");
	}
	void printHelp() const
	{
		std::cout << "This is a generator for the " << MODULE_NAME << " rooting-layer system module. " << std::endl << std::endl;
		std::cout << "Options: " << std::endl;
		std::cout << "\t" << this->vector2string(this->helpArguments) << "\t\tPrint the help information. " << std::endl;
		std::cout << "\t" << this->vector2string(this->inputArguments) << "<path>\t\tSpecify the input database JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputWhitelistArguments) << "<path>\t\tSpecify the output whitelist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputBlacklistArguments) << "<path>\t\tSpecify the output blacklist configuration JSON file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputPathTesterArguments) << "<path>\t\tSpecify the output path tester shell script file path. " << std::endl;
		std::cout << "\t" << this->vector2string(this->outputTargetArguments) << "<path>\t\tSpecify the output Tricky Store target text file path. " << std::endl << std::endl;
		std::cout << "Notes:" << std::endl;
		std::cout << "\t1) Arguments are processed sequentially. If the same argument is provided multiple times, the last one will overwrite the previous ones. Unrecognized options or missing option values will be skipped with a warning. " << std::endl;
		std::cout << "\t2) The input database is required. The program will return EOF (" << EOF << ") if the input file path cannot be parsed. " << std::endl;
		std::cout << "\t3) The outputs are optional. If ``.`` is passed, the program will print to the console. The program will create the parent directory if it does not exist. If an output is not specified, it will be regarded as successful. " << std::endl;
		std::cout << "\t4) Only when all outputs are successful, the program will return EXIT_SUCCESS (" << EXIT_SUCCESS << "). If one or more outputs are unsuccessful, the program will return EXIT_FAILURE (" << EXIT_FAILURE << "). " << std::endl << std::endl;
		return;
	}
	bool handleFolder(const std::string& filePath)
	{
		try
		{
			std::filesystem::path p(filePath);
			const std::filesystem::path folderPath = p.parent_path();
			if (folderPath.empty()) // os.path.split("test.txt")[0] = ""
				return true;
			else if (std::filesystem::exists(folderPath))
				return std::filesystem::is_directory(folderPath);
			else
				return std::filesystem::create_directories(folderPath) && std::filesystem::is_directory(folderPath);
		}
		catch (...)
		{
			return false;
		}
	}
	std::string array2string(const nlohmann::json& elements, const std::string& separator, const std::string& p, const std::string& s) const
	{
		std::stringstream ss{};
		for (nlohmann::json::const_iterator arrayIt = elements.begin(); arrayIt != elements.end(); ++arrayIt)
			if (arrayIt->is_string())
			{
				ss << p + arrayIt->get<std::string>() + s;
				for (++arrayIt; arrayIt != elements.end(); ++arrayIt)
					if (arrayIt->is_string())
						ss << separator + p + arrayIt->get<std::string>() + s;
			}
		return ss.str();
	}
	
public:
	Generator()
	{
		
	}
	bool parseArguments(int argc, char* argv[], bool& exitFlag)
	{
		this->flag = 0;
		this->inputFilePath = DATABASE_JSON;
		this->outputWhitelistFilePath.clear();
		this->outputBlacklistFilePath.clear();
		this->outputPathTesterFilePath.clear();
		this->outputTargetFilePath.clear();
		bool missingArgument = false;
		std::vector<size_t> invalidArgumentIndexes{};
		for (int i = 1; i < argc; ++i)
			if (std::find(helpArguments.begin(), helpArguments.end(), argv[i]) != helpArguments.end())
			{
				this->printHelp();
				exitFlag = true;
				return true;
			}
			else if (std::find(inputArguments.begin(), inputArguments.end(), argv[i]) != inputArguments.end())
				if (++i < argc)
					this->inputFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputWhitelistArguments.begin(), outputWhitelistArguments.end(), argv[i]) != outputWhitelistArguments.end())
				if (++i < argc)
					this->outputWhitelistFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else if (std::find(outputBlacklistArguments.begin(), outputBlacklistArguments.end(), argv[i]) != outputBlacklistArguments.end())
				if (++i < argc)
					this->outputBlacklistFilePath = argv[i];
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
					this->outputTargetFilePath = argv[i];
				else
				{
					missingArgument = true;
					break;
				}
			else
				invalidArgumentIndexes.push_back(i);
		if (missingArgument)
			std::cout << "Warning: The corresponding value for the last argument is missing. " << std::endl;
		const size_t invalidArgumentCount = invalidArgumentIndexes.size();
		if (1 == invalidArgumentCount)
			std::cout << "Warning: The argument whose index is [" << invalidArgumentIndexes[0] << "] could not be recognized, which has been skipped. " << std::endl;
		else if (invalidArgumentCount >= 2)
		{
			std::cout << "Warning: " << invalidArgumentIndexes.size() << " arguments, whose indexes are ";
			if (2 == invalidArgumentCount)
				std::cout << "[" << invalidArgumentIndexes[0] << "] and [" << invalidArgumentIndexes[1] << "]";
			else
			{
				for (size_t i = 0; i < invalidArgumentCount - 1; ++i)
					std::cout << "[" << invalidArgumentIndexes[i] << "], ";
				std::cout << "and [" << invalidArgumentIndexes[invalidArgumentCount - 1] << "]";
			}
			std::cout << ", could not be recognized, which have been skipped. " << std::endl;
		}
		if (this->inputFilePath.empty())
			return false;
		else
		{
			this->flag = 1;
			return true;
		}
	}
	bool parseJSON()
	{
		if (this->flag & 1/* 0b000001 */)
		{
			this->flag &= 1/* 0b000001 */;
			try
			{
				std::ifstream inputFile(this->inputFilePath);
				if (inputFile.is_open())
				{
					try
					{
						this->j = nlohmann::json::parse(inputFile);
						
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
						const std::string cppVersion = (std::string)CPP_VERSION + "+";
						if (this->j.contains("V") && this->j["V"].is_string() && this->j["V"].get<std::string>().substr(0, cppVersion.length()) == cppVersion)
							if (this->j.contains("U") && this->j["U"].is_string() && REGEX_PATTERN == this->j["U"].get<std::string>())
							{
								if (1 == removedKeyCount)
									std::cout << "Warning: A root key is invalid, which has been removed. " << std::endl;
								else if (removedKeyCount)
									std::cout << "Warning: " << removedKeyCount << " root keys are invalid, which have been removed. " << std::endl;
							}
							else
								std::cout << "Warning: This program expects the regex pattern \"" << REGEX_PATTERN << "\" while the input database is not. " << std::endl;
						else
							std::cout << "Warning: This program expects the version " << CPP_VERSION << " while the input database is not, which may result in warnings. " << std::endl;
						
						/* Second-level */
						removedKeyCount = 0;
						const std::regex pattern(REGEX_PATTERN);
						if (this->j.contains("C") && this->j["C"].is_object())
						{
							for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); )
								if (entryIt.key().length() == 1 && 'A' <= entryIt.key()[0] && entryIt.key()[0] <= 'Z' && entryIt.value().is_array())
								{
									int removedValueCount = 0;
									for (nlohmann::json::iterator arrayIt = entryIt.value().begin(); arrayIt != entryIt.value().end(); )
										if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), pattern))
											++arrayIt;
										else
										{
											arrayIt = entryIt.value().erase(arrayIt);
											++removedValueCount;
										}
									if (1 == removedValueCount)
										std::cout << "Warning: A value in $C_" << entryIt.key() << "$ is invalid, which has been removed. " << std::endl;
									else if (removedValueCount)
										std::cout << "Warning: " << removedValueCount << " values in $C_" << entryIt.key() << "$ are invalid, which have been removed. " << std::endl;
									++entryIt;
								}
								else
								{
									entryIt = this->j["C"].erase(entryIt);
									++removedKeyCount;
								}
							if (1 == removedKeyCount)
								std::cout << "Warning: A key in $C$ is invalid, which has been removed. " << std::endl;
							else if (removedKeyCount)
								std::cout << "Warning: " << removedKeyCount << " keys in $C$ are invalid, which have been removed. " << std::endl;
						}
						else
						{
							this->j["C"] = nlohmann::json::object();
							std::cout << "Warning: Initialized $C$ as an empty dictionary. " << std::endl;
						}
						if (this->j.contains("D") && this->j["D"].is_array())
						{
							int removedValueCount = 0;
							for (nlohmann::json::iterator arrayIt = this->j["D"].begin(); arrayIt != this->j["D"].end(); )
								if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), pattern))
									++arrayIt;
								else
								{
									arrayIt = this->j["D"].erase(arrayIt);
									++removedValueCount;
								}
							if (1 == removedValueCount)
								std::cout << "Warning: A value in $D$ is invalid, which has been removed. " << std::endl;
							else if (removedValueCount)
								std::cout << "Warning: " << removedValueCount << " values in $D$ are invalid, which have been removed. " << std::endl;
						}
						else
						{
							this->j["D"] = nlohmann::json::array();
							std::cout << "Warning: Initialized $D$ as an empty array. " << std::endl;
						}
						if (this->j.contains("M") && this->j["M"].is_array())
						{
							int removedValueCount = 0;
							for (nlohmann::json::iterator arrayIt = this->j["M"].begin(); arrayIt != this->j["M"].end(); )
								if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), pattern))
									++arrayIt;
								else
								{
									arrayIt = this->j["M"].erase(arrayIt);
									++removedValueCount;
								}
							if (1 == removedValueCount)
								std::cout << "Warning: A value in $M$ is invalid, which has been removed. " << std::endl;
							else if (removedValueCount)
								std::cout << "Warning: " << removedValueCount << " values in $M$ are invalid, which have been removed. " << std::endl;
						}
						else
						{
							this->j["M"] = nlohmann::json::array();
							std::cout << "Warning: Initialized $M$ as an empty array. " << std::endl;
						}
						removedKeyCount = 0;
						if (this->j.contains("N") && this->j["N"].is_object())
						{
							for (nlohmann::json::iterator outerEntryIt = this->j["N"].begin(); outerEntryIt != this->j["N"].end(); )
								if (std::regex_match(outerEntryIt.key(), pattern) && outerEntryIt.value().is_object())
								{
									int removedEntryCount = 0;
									for (nlohmann::json::iterator innerEntryIt = outerEntryIt.value().begin(); innerEntryIt != outerEntryIt.value().end(); )
										if (std::regex_match(innerEntryIt.key(), pattern) && innerEntryIt.value().is_boolean())
											++innerEntryIt;
										else
										{
											innerEntryIt = outerEntryIt.value().erase(innerEntryIt);
											++removedEntryCount;
										}
									if (1 == removedEntryCount)
										std::cout << "Warning: An entry in " << outerEntryIt.key() << " of $N$ is invalid, which has been removed. " << std::endl;
									else if (removedEntryCount)
										std::cout << "Warning: " << removedEntryCount << " entries in " << outerEntryIt.key() << " of $N$ are invalid, which have been removed. " << std::endl;
									++outerEntryIt;
								}
								else
								{
									outerEntryIt = this->j["N"].erase(outerEntryIt);
									++removedKeyCount;
								}
							if (1 == removedKeyCount)
								std::cout << "Warning: A key in $N$ is invalid, which has been removed. " << std::endl;
							else if (removedKeyCount)
								std::cout << "Warning: " << removedKeyCount << " keys in $N$ are invalid, which have been removed. " << std::endl;
						}
						else
						{
							this->j["N"] = nlohmann::json::object();
							std::cout << "Warning: Initialized $N$ as an empty dictionary. " << std::endl;
						}
						if (this->j.contains("S") && this->j["S"].is_array())
						{
							int removedValueCount = 0;
							for (nlohmann::json::iterator arrayIt = this->j["S"].begin(); arrayIt != this->j["S"].end(); )
								if (arrayIt->is_string() && std::regex_match(arrayIt->get<std::string>(), pattern))
									++arrayIt;
								else
								{
									arrayIt = this->j["S"].erase(arrayIt);
									++removedValueCount;
								}
							if (1 == removedValueCount)
								std::cout << "Warning: A value in $S$ is invalid, which has been removed. " << std::endl;
							else if (removedValueCount)
								std::cout << "Warning: " << removedValueCount << " values in $S$ are invalid, which have been removed. " << std::endl;
						}
						else
						{
							this->j["S"] = nlohmann::json::array();
							std::cout << "Warning: Initialized $S$ as an empty array. " << std::endl;
						}
						if (this->j.contains("T") && this->j["T"].is_object())
						{
							int removedEntryCount = 0;
							for (nlohmann::json::iterator entryIt = this->j["T"].begin(); entryIt != this->j["T"].end(); )
								if (std::regex_match(entryIt.key(), pattern) && entryIt.value().is_boolean())
									++entryIt;
								else
									entryIt = this->j["T"].erase(entryIt);
							if (1 == removedEntryCount)
								std::cout << "Warning: An entry in $T$ is invalid, which has been removed. " << std::endl;
							else if (removedEntryCount)
								std::cout << "Warning: " << removedEntryCount << " entries in $T$ are invalid, which have been removed. " << std::endl;
						}
						else
						{
							this->j["T"] = nlohmann::json::object();
							std::cout << "Warning: Initialized $T$ as an empty dictionary. " << std::endl;
						}
						this->flag |= 2/* 0b000010 */;
					}
					catch (...)
					{
						std::cerr << "Error: Failed to parse the content read from the input database JSON file. " << std::endl;
					}
					inputFile.close();
					return this->flag & 2/* 0b000010 */ && this->flag & 1/* 0b000001 */;
				}
				else
				{
					std::cerr << "Error: Failed to open the input database JSON file. " << std::endl;
					return false;
				}
			}
			catch (...)
			{
				std::cerr << "Error: Failed to parse the input database JSON file. " << std::endl;
				return false;
			}
		}
		else
		{
			std::cerr << "Error: Please parse command-line arguments before paring the input database JSON file. " << std::endl;
			return false;
		}
	}
	bool generateHMAConfigurations()
	{
		if (this->flag & 2/* 0b000010 */ && this->flag & 1/* 0b000001 */)
		{
			this->flag &= 51/* 0b110011 */;
			
			/* commonHMAv92 */
			if (this->outputWhitelistFilePath.empty() && this->outputBlacklistFilePath.empty())
				this->flag |= 12/* 0b001100 */;
			else
			{
				nlohmann::ordered_json commonHMAv92{};
				commonHMAv92["configVersion"] = 92;
				commonHMAv92["detailLog"] = true;
				commonHMAv92["maxLogSize"] = 1024;
				commonHMAv92["forceMountData"] = true;
				commonHMAv92["aggressiveFilter"] = true;
				commonHMAv92["templates"] = nlohmann::ordered_json::object();
				for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
				{
					const std::string whitelistName = "WhitelistC" + entryIt.key();
					commonHMAv92["templates"][whitelistName] = nlohmann::ordered_json::object();
					commonHMAv92["templates"][whitelistName]["isWhitelist"] = true;
					commonHMAv92["templates"][whitelistName]["appList"] = nlohmann::ordered_json::array();
					for (const nlohmann::json& value : entryIt.value())
						commonHMAv92["templates"][whitelistName]["appList"].push_back(value.get<std::string>());
				}
				for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
				{
					const std::string blacklistName = "BlacklistC" + entryIt.key();
					commonHMAv92["templates"][blacklistName] = nlohmann::ordered_json::object();
					commonHMAv92["templates"][blacklistName]["isWhitelist"] = false;
					commonHMAv92["templates"][blacklistName]["appList"] = nlohmann::ordered_json::array();
					for (const nlohmann::json& value : entryIt.value())
						commonHMAv92["templates"][blacklistName]["appList"].push_back(value.get<std::string>());
				}
				commonHMAv92["templates"]["BlacklistD"] = nlohmann::ordered_json::object();
				commonHMAv92["templates"]["BlacklistD"]["isWhitelist"] = false;
				commonHMAv92["templates"]["BlacklistD"]["appList"] = nlohmann::ordered_json::array();
				for (const nlohmann::json& value : this->j["D"])
					commonHMAv92["templates"]["BlacklistD"]["appList"].push_back(value.get<std::string>());
				commonHMAv92["templates"]["BlacklistM"] = nlohmann::ordered_json::object();
				commonHMAv92["templates"]["BlacklistM"]["isWhitelist"] = false;
				commonHMAv92["templates"]["BlacklistM"]["appList"] = nlohmann::ordered_json::array();
				for (const nlohmann::json& value : this->j["M"])
					commonHMAv92["templates"]["BlacklistM"]["appList"].push_back(value.get<std::string>());
				
				/* whitelistHMAv92 */
				if (this->outputWhitelistFilePath.empty())
					this->flag |= 4/* 0b000100 */;
				else
				{
					nlohmann::ordered_json whitelistHMAv92(commonHMAv92);
					whitelistHMAv92["scope"] = nlohmann::json::object();
					for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
						for (const nlohmann::json& value : entryIt.value())
						{
							const std::string packageName = value.get<std::string>();
							whitelistHMAv92["scope"][packageName] = nlohmann::ordered_json::object();
							whitelistHMAv92["scope"][packageName]["useWhitelist"] = true;
							whitelistHMAv92["scope"][packageName]["excludeSystemApps"] = true;
							whitelistHMAv92["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							whitelistHMAv92["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
							whitelistHMAv92["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						}
					for (const nlohmann::json& value : this->j["D"])
					{
						const std::string packageName = value.get<std::string>();
						whitelistHMAv92["scope"][packageName] = nlohmann::ordered_json::object();
						whitelistHMAv92["scope"][packageName]["useWhitelist"] = true;
						whitelistHMAv92["scope"][packageName]["excludeSystemApps"] = true;
						whitelistHMAv92["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
						for (nlohmann::json::iterator entryIt = this->j["C"].begin(); entryIt != this->j["C"].end(); ++entryIt)
							whitelistHMAv92["scope"][packageName]["applyTemplates"].push_back("WhitelistC" + entryIt.key());
						whitelistHMAv92["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						whitelistHMAv92["scope"][packageName]["extraAppList"].push_back(packageName);
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["N"].begin(); outerEntryIt != this->j["N"].end(); ++outerEntryIt)
						if (whitelistHMAv92["scope"].contains(outerEntryIt.key()))
							for (nlohmann::json::const_iterator innerEntryIt = outerEntryIt.value().begin(); innerEntryIt != outerEntryIt.value().end(); ++innerEntryIt)
							{
								if (innerEntryIt.value().get<bool>()) // add to the ``extraAppList`` if it is not in any of the templates applied
								{
									bool addingFlag = !whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].contains(innerEntryIt.key());
									if (addingFlag)
										for (const nlohmann::ordered_json& value : whitelistHMAv92["scope"][outerEntryIt.key()]["applyTemplates"])
										{
											const std::string templateName = value.get<std::string>();
											if (whitelistHMAv92["templates"].contains(templateName) && whitelistHMAv92["templates"][templateName].contains("isWhitelist") && whitelistHMAv92["templates"][templateName]["isWhitelist"].get<bool>() && whitelistHMAv92["templates"][templateName].contains("appList") && whitelistHMAv92["templates"][templateName]["appList"].contains(innerEntryIt.key()))
											{
												addingFlag = false;
												break;
											}
										}
									if (addingFlag)
										whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].push_back(innerEntryIt.key());
								}
								else // Search for all the whitelist-type template where the package name is located from the applied template list and unzip the templates to "extraAppList" without the package name
									for (nlohmann::ordered_json::iterator templateArrayIt = whitelistHMAv92["scope"][outerEntryIt.key()]["applyTemplates"].begin(); templateArrayIt != whitelistHMAv92["scope"][outerEntryIt.key()]["applyTemplates"].end(); )
									{
										const std::string templateName = templateArrayIt.value().get<std::string>();
										if (whitelistHMAv92["templates"].contains(templateName) && whitelistHMAv92["templates"][templateName].contains("isWhitelist") && whitelistHMAv92["templates"][templateName]["isWhitelist"].is_boolean() && whitelistHMAv92["templates"][templateName]["isWhitelist"].get<bool>() && whitelistHMAv92["templates"][templateName].contains("appList") && whitelistHMAv92["templates"][templateName]["appList"].is_array() && std::find(whitelistHMAv92["templates"][templateName]["appList"].begin(), whitelistHMAv92["templates"][templateName]["appList"].end(), innerEntryIt.key()) != whitelistHMAv92["templates"][templateName]["appList"].end())
										{
											for (const nlohmann::ordered_json& value : whitelistHMAv92["templates"][templateName]["appList"])
											{
												const std::string packageName = value.get<std::string>();
												if (!whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].contains(packageName))
													whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].push_back(packageName);
											}
											templateArrayIt = whitelistHMAv92["scope"][outerEntryIt.key()]["applyTemplates"].erase(templateArrayIt);
										}
										else
											++templateArrayIt;
										std::sort(whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].begin(), whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].end());
										if (std::find(whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].begin(), whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].end(), innerEntryIt.key()) != whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].end())
											whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].erase(std::remove(whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].begin(), whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].end(), innerEntryIt.key()), whitelistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].end());
									}
							}
					if ("." == this->outputWhitelistFilePath)
					{
						std::cout << whitelistHMAv92.dump() << std::endl;
						this->flag |= 4/* 0b000100 */;
					}
					else if (this->handleFolder(this->outputWhitelistFilePath))
						try
						{
							std::ofstream outputWhitelistFile(this->outputWhitelistFilePath);
							if (outputWhitelistFile.is_open())
							{
								outputWhitelistFile << whitelistHMAv92.dump();
								outputWhitelistFile.close();
								this->flag |= 4/* 0b000100 */;
							}
							else
								std::cerr << "Error: Failed to open the output whitelist configuration JSON file. " << std::endl;
						}
						catch (...)
						{
							std::cerr << "Error: Failed to generate the output whitelist configuration JSON file. " << std::endl;
						}
					else
						std::cerr << "Error: Failed to handle the parent directory for the output whitelist configuration JSON file. " << std::endl;
				}
				
				/* blacklistHMAv92 */
				if (this->outputBlacklistFilePath.empty())
					this->flag |= 8/* 0b001000 */;
				else
				{
					nlohmann::ordered_json blacklistHMAv92(commonHMAv92);
					blacklistHMAv92["scope"] = nlohmann::json::object();
					for (nlohmann::json::const_iterator outerEntryIt = this->j["C"].begin(); outerEntryIt != this->j["C"].end(); ++outerEntryIt)
						for (const nlohmann::json& value : outerEntryIt.value())
						{
							const std::string packageName = value.get<std::string>();
							blacklistHMAv92["scope"][packageName] = nlohmann::ordered_json::object();
							blacklistHMAv92["scope"][packageName]["useWhitelist"] = false;
							blacklistHMAv92["scope"][packageName]["excludeSystemApps"] = false;
							blacklistHMAv92["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							for (nlohmann::json::const_iterator innerEntryIt = this->j["C"].begin(); innerEntryIt != this->j["C"].end(); ++innerEntryIt)
								if (innerEntryIt != outerEntryIt)
									blacklistHMAv92["scope"][packageName]["applyTemplates"].push_back("BlacklistC" + innerEntryIt.key());
							blacklistHMAv92["scope"][packageName]["applyTemplates"].push_back("BlacklistD");
							blacklistHMAv92["scope"][packageName]["applyTemplates"].push_back("BlacklistM");
							blacklistHMAv92["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						}
					for (const nlohmann::json& outerValue : this->j["D"])
					{
						const std::string outerPackageName = outerValue.get<std::string>();
						blacklistHMAv92["scope"][outerPackageName] = nlohmann::ordered_json::object();
						blacklistHMAv92["scope"][outerPackageName]["useWhitelist"] = false;
						blacklistHMAv92["scope"][outerPackageName]["excludeSystemApps"] = false;
						blacklistHMAv92["scope"][outerPackageName]["applyTemplates"] = nlohmann::ordered_json::array();
						blacklistHMAv92["scope"][outerPackageName]["applyTemplates"].push_back("BlacklistM");
						blacklistHMAv92["scope"][outerPackageName]["extraAppList"] = nlohmann::ordered_json::array();
						for (const nlohmann::json& innerValue : this->j["D"])
						{
							const std::string innerPackageName = innerValue.get<std::string>();
							if (outerPackageName != innerPackageName)
								blacklistHMAv92["scope"][outerPackageName]["extraAppList"].push_back(innerPackageName);
						}
					}
					for (nlohmann::json::const_iterator outerEntryIt = this->j["N"].begin(); outerEntryIt != this->j["N"].end(); ++outerEntryIt)
						if (blacklistHMAv92["scope"].contains(outerEntryIt.key()))
							for (nlohmann::json::const_iterator innerEntryIt = outerEntryIt.value().begin(); innerEntryIt != outerEntryIt.value().end(); ++innerEntryIt)
							{
									if (innerEntryIt.value().get<bool>()) // Search for all the blacklist-type templates where the package name is located from the applied template list and unzip the templates to "extraAppList" without the package name
									for (nlohmann::ordered_json::iterator templateArrayIt = blacklistHMAv92["scope"][outerEntryIt.key()]["applyTemplates"].begin(); templateArrayIt != blacklistHMAv92["scope"][outerEntryIt.key()]["applyTemplates"].end(); )
									{
										const std::string templateName = templateArrayIt.value().get<std::string>();
										if (blacklistHMAv92["templates"].contains(templateName) && blacklistHMAv92["templates"][templateName].contains("isWhitelist") && blacklistHMAv92["templates"][templateName]["isWhitelist"].is_boolean() && !blacklistHMAv92["templates"][templateName]["isWhitelist"].get<bool>() && blacklistHMAv92["templates"][templateName].contains("appList") && blacklistHMAv92["templates"][templateName]["appList"].is_array() && std::find(blacklistHMAv92["templates"][templateName]["appList"].begin(), blacklistHMAv92["templates"][templateName]["appList"].end(), innerEntryIt.key()) != blacklistHMAv92["templates"][templateName]["appList"].end())
										{
											for (const nlohmann::ordered_json& value : blacklistHMAv92["templates"][templateName]["appList"])
											{
												const std::string packageName = value.get<std::string>();
												if (!blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].contains(packageName))
													blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].push_back(packageName);
											}
											templateArrayIt = blacklistHMAv92["scope"][outerEntryIt.key()]["applyTemplates"].erase(templateArrayIt);
										}
										else
											++templateArrayIt;
										std::sort(blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].begin(), blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].end());
										if (std::find(blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].begin(), blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].end(), innerEntryIt.key()) != blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].end())
											blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].erase(std::remove(blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].begin(), blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].end(), innerEntryIt.key()), blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].end());
									}
								else // add to the ``extraAppList`` if it is not in any of the templates applied
								{
									bool addingFlag = !blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].contains(innerEntryIt.key());
									if (addingFlag)
										for (const nlohmann::ordered_json& value : blacklistHMAv92["scope"][outerEntryIt.key()]["applyTemplates"])
										{
											const std::string templateName = value.get<std::string>();
											if (blacklistHMAv92["templates"].contains(templateName) && blacklistHMAv92["templates"][templateName].contains("isWhitelist") && !blacklistHMAv92["templates"][templateName]["isWhitelist"].get<bool>() && blacklistHMAv92["templates"][templateName].contains("appList") && blacklistHMAv92["templates"][templateName]["appList"].contains(innerEntryIt.key()))
											{
												addingFlag = false;
												break;
											}
										}
									if (addingFlag)
										blacklistHMAv92["scope"][outerEntryIt.key()]["extraAppList"].push_back(innerEntryIt.key());
								}
							}
					if ("." == this->outputBlacklistFilePath)
					{
						std::cout << blacklistHMAv92.dump() << std::endl;
						this->flag |= 8/* 0b001000 */;
					}
					else if (this->handleFolder(this->outputBlacklistFilePath))
						try
						{
							std::ofstream outputBlacklistFile(this->outputBlacklistFilePath);
							if (outputBlacklistFile.is_open())
							{
								outputBlacklistFile << blacklistHMAv92.dump();
								outputBlacklistFile.close();
								this->flag |= 8/* 0b001000 */;
							}
							else
								std::cerr << "Error: Failed to open the output blacklist configuration JSON file. " << std::endl;
						}
						catch (...)
						{
							std::cerr << "Error: Failed to generate the output blacklist configuration JSON file. " << std::endl;
						}
					else
						std::cerr << "Error: Failed to handle the parent directory for the output blacklist configuration JSON file. " << std::endl;
				}
			}
			
			/* Return */
			return this->flag & 8/* 0b001000 */ && this->flag & 4/* 0b000100 */ && this->flag & 2/* 0b000010 */ && this->flag & 1/* 0b000001 */;
		}
		else
		{
			std::cerr << "Error: Please parse the input database JSON file before generating the HMA configuration JSON files. " << std::endl;
			return false;
		}
	}
	bool generatePathTester()
	{
		if (this->flag & 2/* 0b000010 */ && this->flag & 1/* 0b000001 */)
		{
			this->flag &= 47/* 0b101111 */;
			if (this->outputPathTesterFilePath.empty())
				this->flag |= 16/* 0b010000 */;
			else
			{
				std::stringstream ss{};
				ss << "#!/system/bin/sh\n";
				ss << "readonly EXIT_SUCCESS=0\n";
				ss << "readonly EXIT_FAILURE=1\n\n";
				ss << "readonly EOF=-1\n\n";
				ss << "errorLevel=${EXIT_SUCCESS}\n";
				ss << "if echo \"${EXTERNAL_STORAGE}\" | grep -qE \"^(/[A-Za-z0-9_-]+)+$\";\n";
				ss << "then\n";
				ss << "\treadonly folders=\"/data/data /data/user/0 /data/user_de/0 ${EXTERNAL_STORAGE}/Android/data\"\n";
				ss << "\treadonly wxDownloadFolderPath=\"${EXTERNAL_STORAGE}/Download/WechatXposed\"\n";
				ss << "else\n";
				ss << "\treadonly folders=\"/data/data /data/user/0 /data/user_de/0 /sdcard/Android/data\"\n";
				ss << "\treadonly wxDownloadFolderPath=\"/sdcard/Download/WechatXposed\"\n";
				ss << "fi\n\n";
				ss << "if [[ $(id -u) -eq 0 ]];\n";
				ss << "then\n";
				ss << "\terrorLevel=${EOF}\n";
				ss << "\techo \"You are running this script as root. Please run it as a regular user.\"\n";
				ss << "\texit ${errorLevel}\n";
				ss << "else\n";
				ss << "\techo -e \"The execution of the path tester has begun. \"\n";
				ss << "fi\n\n";
				ss << "readonly D=" + this->array2string(this->j["D"], " ", "\"", "\"") + "\n";
				ss << "for d in ${D};\n";
				ss << "do\n";
				ss << "\tfor folder in ${folders};\n";
				ss << "\tdo\n";
				ss << "\t\tsensitivePath=\"${folder}/${d}\"\n";
				ss << "\t\tif [[ -e \"${sensitivePath}\" ]];\n";
				ss << "\t\tthen\n";
				ss << "\t\t\terrorLevel=${EXIT_FAILURE}\n";
				ss << "\t\t\techo \"- Found \\\"${sensitivePath}\\\" (\\$D\\$). \"\n";
				ss << "\t\tfi\n";
				ss << "\tdone\n";
				ss << "done\n\n";
				ss << "readonly M=" + this->array2string(this->j["M"], " ", "\"", "\"") + "\n";
				ss << "for m in ${M};\n";
				ss << "do\n";
				ss << "\tfor folder in ${folders};\n";
				ss << "\tdo\n";
				ss << "\t\tsensitivePath=\"${folder}/${m}\"\n";
				ss << "\t\tif [[ -e \"${sensitivePath}\" ]];\n";
				ss << "\t\tthen\n";
				ss << "\t\t\terrorLevel=${EXIT_FAILURE}\n";
				ss << "\t\t\techo \"- Found \\\"${sensitivePath}\\\" (\\$M\\$). \"\n";
				ss << "\t\tfi\n";
				ss << "\tdone\n";
				ss << "done\n\n";
				ss << "if [[ -e \"${wxDownloadFolderPath}\" ]];\n";
				ss << "then\n";
				ss << "\terrorLevel=${EXIT_FAILURE}\n";
				ss << "\techo \"- Found \\\"${wxDownloadFolderPath}\\\" (\\$M_P\\$). \"\n";
				ss << "fi\n\n";
				ss << "if [[ ${EXIT_SUCCESS} -eq ${errorLevel} ]];\n";
				ss << "then\n";
				ss << "\techo \"Finished scanning as a regular user. You should have bypass the path detection.\"\n";
				ss << "else\n";
				ss << "\techo \"Finished scanning as a regular user. Your LRFP environments may have been exposed. \"\n";
				ss << "fi\n\n";
				ss << "exit ${errorLevel}\n";
				if ("." == this->outputPathTesterFilePath)
				{
					std::cout << ss.str() << std::endl;
					this->flag |= 16/* 0b010000 */;
				}
				else if (this->handleFolder(this->outputPathTesterFilePath))
					try
					{
						std::ofstream outputPathTesterFile(this->outputPathTesterFilePath);
						if (outputPathTesterFile.is_open())
						{
							outputPathTesterFile << ss.str();
							outputPathTesterFile.close();
							this->flag |= 16/* 0b010000 */;
						}
						else
							std::cerr << "Error: Failed to open the output path tester script file. " << std::endl;
					}
					catch (...)
					{
						std::cerr << "Error: Failed to generate the output path tester script file. " << std::endl;
					}
				else
					std::cerr << "Error: Failed to handle the parent directory for the output path tester script file. " << std::endl;
			}
			return this->flag & 16/* 0b010000 */ && this->flag & 2/* 0b000010 */ && this->flag & 1/* 0b000001 */;
		}
		else
		{
			std::cerr << "Error: Please parse the input database JSON file before generating the path tester script file. " << std::endl;
			return false;
		}
	}
	bool generateTrickyStoreTarget()
	{
		if (this->flag & 2/* 0b000010 */ && this->flag & 1/* 0b000001 */)
		{
			this->flag &= 31/* 0b011111 */;
			if (this->outputTargetFilePath.empty())
				this->flag |= 32/* 0b100000 */;
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
				if ("." == this->outputTargetFilePath)
				{
					for (const std::string& packageName : targetPackageNames)
						std::cout << packageName << std::endl;
					this->flag |= 32/* 0b100000 */;
				}
				else if (this->handleFolder(this->outputTargetFilePath))
					try
					{
						std::ofstream outputTargetFile(this->outputTargetFilePath);
						if (outputTargetFile.is_open())
						{
							for (const std::string& packageName : targetPackageNames)
								outputTargetFile << packageName << std::endl;
							outputTargetFile.close();
							this->flag |= 32/* 0b100000 */;
						}
						else
							std::cerr << "Error: Failed to open the output Tricky Store target text file. " << std::endl;
					}
					catch (...)
					{
						std::cerr << "Error: Failed to generate the output Tricky Store target text file. " << std::endl;
					}
				else
					std::cerr << "Error: Failed to handle the parent directory for the output Tricky Store target text file. " << std::endl;
			}
			return this->flag & 32/* 0b100000 */ && this->flag & 2/* 0b000010 */ && this->flag & 1/* 0b000001 */;
		}
		else
		{
			std::cerr << "Error: Please parse the input database JSON file before generating the Tricky Store target text file. " << std::endl;
			return false;
		}
	}
	unsigned char getFlag() const
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
	else if (parsingFlag && generator.parseJSON())
		return generator.generateHMAConfigurations() && generator.generatePathTester() && generator.generateTrickyStoreTarget() ? EXIT_SUCCESS : EXIT_FAILURE;
	else
		return EOF;
}