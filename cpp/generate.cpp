#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <set>
#include "nlohmann/json.hpp"


class Generator
{
private:
	short flag = 0;
	std::string inputFilePath{};
	std::string outputWhitelistFilePath{};
	std::string outputBlacklistFilePath{};
	std::string outputPathTesterFilePath{};
	std::string outputTargetFilePath{};
	std::vector<std::string> inputArguments{ "i", "/i", "-i", "input", "/input", "--input" };
	std::vector<std::string> outputWhitelistArguments{ "ow", "/ow", "-ow", "outputWhitelist", "/outputWhitelist", "--outputWhitelist" };
	std::vector<std::string> outputBlacklistArguments{ "ob", "/ob", "-ob", "outputBlacklist", "/outputBlacklist", "--outputBlacklist" };
	std::vector<std::string> outputPathTesterArguments{ "op", "/op", "-op", "outputPathTester", "/outputPathTester", "--outputPathTester" };
	std::vector<std::string> outputTargetArguments{ "ot", "/ot", "-ot", "outputTarget", "/outputTarget", "--outputTarget" };
	nlohmann::json j{};
	bool flagCG = false, flagCZ = false, flagD = false, flagM = false, flagO = false, flagS = false, flagT = false;
	
public:
	Generator()
	{
		
	}
	bool parseArguments(int argc, char* argv[])
	{
		this->flag = 0;
		this->inputFilePath.clear();
		this->outputWhitelistFilePath.clear();
		this->outputBlacklistFilePath.clear();
		this->outputTargetFilePath.clear();
		std::vector<size_t> invalidArgumentIndexes{};
		for (int i = 0; i < argc; ++i)
			if (std::find(inputArguments.begin(), inputArguments.end(), argv[i]) != inputArguments.end())
				if (++i < argc)
					this->inputFilePath = argv[i];
				else
					break;
			else if (std::find(outputWhitelistArguments.begin(), outputWhitelistArguments.end(), argv[i]) != outputWhitelistArguments.end())
				if (++i < argc)
					this->outputWhitelistFilePath = argv[i];
				else
					break;
			else if (std::find(outputBlacklistArguments.begin(), outputBlacklistArguments.end(), argv[i]) != outputBlacklistArguments.end())
				if (++i < argc)
					this->outputBlacklistFilePath = argv[i];
				else
					break;
			else if (std::find(outputTargetArguments.begin(), outputTargetArguments.end(), argv[i]) != outputTargetArguments.end())
				if (++i < argc)
					this->outputTargetFilePath = argv[i];
				else
					break;
			else
				invalidArgumentIndexes.push_back(i);
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
		if (this->flag & 1)
		{
			this->flag &= 1;
			try
			{
				std::ifstream inputFile(this->inputFilePath);
				if (inputFile.is_open())
				{
					try
					{
						this->j = nlohmann::json::parse(inputFile);
						if (this->j.contains("C") && this->j["C"].is_object() && this->j["C"].contains("G") && this->j["C"]["G"].is_array() && !this->j["C"]["G"].empty())
						{
							this->j["C"]["G"].erase(std::remove_if(this->j["C"]["G"].begin(), this->j["C"]["G"].end(), [](const nlohmann::json& item) { return !item.is_string(); }), this->j["C"]["G"].end());
							this->flagCG = true;
						}
						else
							this->flagCG = false;
						if (this->j.contains("C") && this->j["C"].is_object() && this->j["C"].contains("Z") && this->j["C"]["Z"].is_array() && !this->j["C"]["Z"].empty())
						{
							this->j["C"]["Z"].erase(std::remove_if(this->j["C"]["Z"].begin(), this->j["C"]["Z"].end(), [](const nlohmann::json& item) { return !item.is_string(); }), this->j["C"]["Z"].end());
							this->flagCZ = true;
						}
						else
							this->flagCZ = false;
						if (this->j.contains("D") && this->j["D"].is_array() && !this->j["D"].empty())
						{
							this->j["D"].erase(std::remove_if(this->j["D"].begin(), this->j["D"].end(), [](const nlohmann::json& item) { return !item.is_string(); }), this->j["D"].end());
							this->flagD = true;
						}
						else
							this->flagD = false;
						if (this->j.contains("M") && this->j["M"].is_array() && !this->j["M"].empty())
						{
							this->j["M"].erase(std::remove_if(this->j["M"].begin(), this->j["M"].end(), [](const nlohmann::json& item) { return !item.is_string(); }), this->j["M"].end());
							this->flagM = true;
						}
						else
							this->flagM = false;
						if (this->j.contains("N") && this->j["N"].is_object() && !this->j["N"].empty())
						{
							for (auto it = this->j["N"].begin(); it != this->j["N"].end(); ++it)
								if (it.value().is_array() && !it.value().empty())
									it.value().erase(std::remove_if(it.value().begin(), it.value().end(), [](const nlohmann::json& item) { return !item.is_string(); }), it.value().end());
								else
									it.value() = nlohmann::json::array();
							this->flagO = true;
						}
						else
							this->flagO = false;
						if (this->j.contains("S") && this->j["S"].is_array() && !this->j["S"].empty())
						{
							this->j["S"].erase(std::remove_if(this->j["S"].begin(), this->j["S"].end(), [](const nlohmann::json& item) { return !item.is_string(); }), this->j["S"].end());
							this->flagS = true;
						}
						else
							this->flagS = false;
						if (this->j.contains("T") && this->j["T"].is_array() && !this->j["T"].empty())
						{
							this->j["T"].erase(std::remove_if(this->j["T"].begin(), this->j["T"].end(), [](const nlohmann::json& item) { return !item.is_string(); }), this->j["T"].end());
							this->flagT = true;
						}
						else
							this->flagT = false;
						this->flag |= 2;
					}
					catch (...) {}
					inputFile.close();
					return this->flag & 3;
				}
				else
					return false;
			}
			catch (...)
			{
				return false;
			}
		}
		else
			return false;
	}
	bool generateHMAConfigurations()
	{
		if (this->flag & 3/* 0b000011 */)
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
				commonHMAv92["templates"]["WhitelistCG"] = nlohmann::ordered_json::object();
				commonHMAv92["templates"]["WhitelistCG"]["isWhitelist"] = true;
				commonHMAv92["templates"]["WhitelistCG"]["appList"] = nlohmann::ordered_json::array();
				commonHMAv92["templates"]["BlacklistCG"] = nlohmann::ordered_json::object();
				commonHMAv92["templates"]["BlacklistCG"]["isWhitelist"] = false;
				commonHMAv92["templates"]["BlacklistCG"]["appList"] = nlohmann::ordered_json::array();
				if (flagCG)
					for (const auto& item : this->j["C"]["G"])
					{
						commonHMAv92["templates"]["WhitelistCG"]["appList"].push_back(item.get<std::string>());
						commonHMAv92["templates"]["BlacklistCG"]["appList"].push_back(item.get<std::string>());
					}
				commonHMAv92["templates"]["WhitelistCZ"] = nlohmann::ordered_json::object();
				commonHMAv92["templates"]["WhitelistCZ"]["isWhitelist"] = true;
				commonHMAv92["templates"]["WhitelistCZ"]["appList"] = nlohmann::ordered_json::array();
				commonHMAv92["templates"]["BlacklistCZ"] = nlohmann::ordered_json::object();
				commonHMAv92["templates"]["BlacklistCZ"]["isWhitelist"] = false;
				commonHMAv92["templates"]["BlacklistCZ"]["appList"] = nlohmann::ordered_json::array();
				if (flagCZ)
					for (const auto& item : this->j["C"]["Z"])
					{
						commonHMAv92["templates"]["WhitelistCZ"]["appList"].push_back(item.get<std::string>());
						commonHMAv92["templates"]["BlacklistCZ"]["appList"].push_back(item.get<std::string>());
					}
				commonHMAv92["templates"]["BlacklistD"] = nlohmann::ordered_json::object();
				commonHMAv92["templates"]["BlacklistD"]["isWhitelist"] = false;
				commonHMAv92["templates"]["BlacklistD"]["appList"] = nlohmann::ordered_json::array();
				if (flagD)
					for (const auto& item : this->j["D"])
						commonHMAv92["templates"]["BlacklistD"]["appList"].push_back(item.get<std::string>());
				commonHMAv92["templates"]["BlacklistM"] = nlohmann::ordered_json::object();
				commonHMAv92["templates"]["BlacklistM"]["isWhitelist"] = false;
				commonHMAv92["templates"]["BlacklistM"]["appList"] = nlohmann::ordered_json::array();
				if (flagM)
					for (const auto& item : this->j["M"])
						commonHMAv92["templates"]["BlacklistM"]["appList"].push_back(item.get<std::string>());

				/* whitelistHMAv92 */
				if (this->outputWhitelistFilePath.empty())
					this->flag |= 4/* 0b000100 */;
				else
				{
					nlohmann::ordered_json whitelistHMAv92(commonHMAv92);
					whitelistHMAv92["scope"] = nlohmann::json::object();
					if (flagCG)
						for (const auto& item : this->j["C"]["G"])
						{
							const std::string packageName = item.get<std::string>();
							whitelistHMAv92["scope"][packageName] = nlohmann::ordered_json::object();
							whitelistHMAv92["scope"][packageName]["useWhitelist"] = true;
							whitelistHMAv92["scope"][packageName]["excludeSystemApps"] = true;
							whitelistHMAv92["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							whitelistHMAv92["scope"][packageName]["applyTemplates"].push_back("WhitelistCG");
							whitelistHMAv92["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						}
					if (flagCZ)
						for (const auto& item : this->j["C"]["Z"])
						{
							const std::string packageName = item.get<std::string>();
							whitelistHMAv92["scope"][packageName] = nlohmann::ordered_json::object();
							whitelistHMAv92["scope"][packageName]["useWhitelist"] = true;
							whitelistHMAv92["scope"][packageName]["excludeSystemApps"] = true;
							whitelistHMAv92["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							whitelistHMAv92["scope"][packageName]["applyTemplates"].push_back("WhitelistCZ");
							whitelistHMAv92["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						}
					if (flagD)
						for (const auto& item : this->j["D"])
						{
							const std::string packageName = item.get<std::string>();
							whitelistHMAv92["scope"][packageName] = nlohmann::ordered_json::object();
							whitelistHMAv92["scope"][packageName]["useWhitelist"] = true;
							whitelistHMAv92["scope"][packageName]["excludeSystemApps"] = true;
							whitelistHMAv92["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							whitelistHMAv92["scope"][packageName]["applyTemplates"].push_back("WhitelistCG");
							whitelistHMAv92["scope"][packageName]["applyTemplates"].push_back("WhitelistCZ");
							whitelistHMAv92["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
							whitelistHMAv92["scope"][packageName]["extraAppList"].push_back(packageName);
						}
					if (flagO)
						for (auto it = this->j["N"].begin(); it != this->j["N"].end(); ++it)
							if (whitelistHMAv92["scope"].find(it.key()) != whitelistHMAv92["scope"].end())
								for (const auto& item : it.value())
								{
									const std::string packageName = item.get<std::string>();
									if (!packageName.empty())
									{
										if ('+' == packageName[0])
											whitelistHMAv92["scope"][it.key()]["extraAppList"].push_back(packageName.substr(1));
										else if ('-' == packageName[0])
										{
											/* Search for the template where packageName.substr(1) is located and unzip the template to "extraAppList" without packageName.substr(1) */
										}
									}
								}
					if ("." == this->outputWhitelistFilePath)
					{
						std::cout << whitelistHMAv92.dump() << std::endl;
						this->flag |= 4/* 0b000100 */;
					}
					else
						try
						{
							std::ofstream outputWhitelistFile(this->outputWhitelistFilePath);
							if (outputWhitelistFile.is_open())
							{
								outputWhitelistFile << whitelistHMAv92.dump();
								outputWhitelistFile.close();
								this->flag |= 4/* 0b000100 */;
							}
						}
						catch (...) {}
				}
				
				/* blacklistHMAv92 */
				if (this->outputBlacklistFilePath.empty())
					this->flag |= 8/* 0b001000 */;
				else
				{
					nlohmann::ordered_json blacklistHMAv92(commonHMAv92);
					blacklistHMAv92["scope"] = nlohmann::json::object();
					if (flagCG)
						for (const auto& item : this->j["C"]["G"])
						{
							const std::string packageName = item.get<std::string>();
							blacklistHMAv92["scope"][packageName] = nlohmann::ordered_json::object();
							blacklistHMAv92["scope"][packageName]["useWhitelist"] = false;
							blacklistHMAv92["scope"][packageName]["excludeSystemApps"] = false;
							blacklistHMAv92["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							blacklistHMAv92["scope"][packageName]["applyTemplates"].push_back("BlacklistCZ");
							blacklistHMAv92["scope"][packageName]["applyTemplates"].push_back("BlacklistD");
							blacklistHMAv92["scope"][packageName]["applyTemplates"].push_back("BlacklistM");
							blacklistHMAv92["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						}
					if (flagCZ)
						for (const auto& item : this->j["C"]["Z"])
						{
							const std::string packageName = item.get<std::string>();
							blacklistHMAv92["scope"][packageName] = nlohmann::ordered_json::object();
							blacklistHMAv92["scope"][packageName]["useWhitelist"] = false;
							blacklistHMAv92["scope"][packageName]["excludeSystemApps"] = false;
							blacklistHMAv92["scope"][packageName]["applyTemplates"] = nlohmann::ordered_json::array();
							blacklistHMAv92["scope"][packageName]["applyTemplates"].push_back("BlacklistCG");
							blacklistHMAv92["scope"][packageName]["applyTemplates"].push_back("BlacklistD");
							blacklistHMAv92["scope"][packageName]["applyTemplates"].push_back("BlacklistM");
							blacklistHMAv92["scope"][packageName]["extraAppList"] = nlohmann::ordered_json::array();
						}
					if (flagD)
						for (const auto& outerItem : this->j["D"])
						{
							const std::string outerPackageName = outerItem.get<std::string>();
							blacklistHMAv92["scope"][outerPackageName] = nlohmann::ordered_json::object();
							blacklistHMAv92["scope"][outerPackageName]["useWhitelist"] = false;
							blacklistHMAv92["scope"][outerPackageName]["excludeSystemApps"] = false;
							blacklistHMAv92["scope"][outerPackageName]["applyTemplates"] = nlohmann::ordered_json::array();
							blacklistHMAv92["scope"][outerPackageName]["applyTemplates"].push_back("BlacklistM");
							blacklistHMAv92["scope"][outerPackageName]["extraAppList"] = nlohmann::ordered_json::array();
							for (const auto& innerItem : this->j["D"])
							{
								const std::string innerPackageName = innerItem.get<std::string>();
								if (outerPackageName != innerPackageName)
									blacklistHMAv92["scope"][outerPackageName]["extraAppList"].push_back(innerPackageName);
							}
						}
					if (flagO)
						for (auto it = this->j["N"].begin(); it != this->j["N"].end(); ++it)
							if (blacklistHMAv92["scope"].find(it.key()) != blacklistHMAv92["scope"].end())
								for (const auto& item : it.value())
								{
									const std::string packageName = item.get<std::string>();
									if (!packageName.empty())
									{
										if ('-' == packageName[0])
											blacklistHMAv92["scope"][it.key()]["extraAppList"].push_back(packageName.substr(1));
										else if ('+' == packageName[0])
										{
											/* Search for the template where packageName.substr(1) is located and unzip the template to "extraAppList" without packageName.substr(1) */
										}
									}
								}
					if ("." == this->outputBlacklistFilePath)
					{
						std::cout << blacklistHMAv92.dump() << std::endl;
						this->flag |= 8/* 0b001000 */;
					}
					else
						try
						{
							std::ofstream outputBlacklistFile(this->outputBlacklistFilePath);
							if (outputBlacklistFile.is_open())
							{
								outputBlacklistFile << blacklistHMAv92.dump();
								outputBlacklistFile.close();
								this->flag |= 8/* 0b001000 */;
							}
						}
						catch (...) {}
				}
			}
			
			/* Return */
			return this->flag & 15/* 0b001111 */;
		}
		else
			return false;
	}
	bool generatePathTester()
	{
		if (this->flag & 3/* 0b000011 */)
		{
			this->flag &= 47/* 0b101111 */;
			if (!this->outputPathTesterFilePath.empty())
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
				if (flagD)
				{
					for (const auto& item : this->j["D"])
					{
						const std::string packageName = item.get<std::string>();
						ss << "for folder in ${folders};\n";
						ss << "do\n";
						ss << "\tsensitivePath=\"${folder}/" << packageName << "\"\n";
						ss << "\tif [[ -e \"${sensitivePath}\" ]];\n";
						ss << "then\n";
						ss << "\t\terrorLevel=${EXIT_FAILURE}\n";
						ss << "\t\techo \"- Found \\\"${sensitivePath}\\\" (\\$D\\$). \"\n";
						ss << "\tfi\n";
						ss << "done\n";
					}
					ss << "\n";
				}
				if (flagM)
				{
					for (const auto& item : this->j["M"])
					{
						const std::string packageName = item.get<std::string>();
						ss << "for folder in ${folders};\n";
						ss << "do\n";
						ss << "\tsensitivePath=\"${folder}/" << packageName << "\"\n";
						ss << "\tif [[ -e \"${sensitivePath}\" ]];\n";
						ss << "then\n";
						ss << "\t\terrorLevel=${EXIT_FAILURE}\n";
						ss << "\t\techo \"- Found \\\"${sensitivePath}\\\" (\\$M\\$). \"\n";
						ss << "\tfi\n";
						ss << "done\n";
					}
					ss << "\n";
				}
				ss << "if [[ -e \"${wxDownloadFolderPath}\" ]];\n";
				ss << "then\n";
				ss << "\terrorLevel=${EXIT_FAILURE}\n";
				ss << "\techo \"- Found \\\"${wxDownloadFolderPath}\\\" (LRFP). \"\n";
				ss << "fi\n\n";
				ss << "if [[ ${EXIT_SUCCESS} -eq ${errorLevel} ]];\n";
				ss << "then\n";
				ss << "\techo \"Finished scanning as a regular user. You should have bypass the path detection.\"\n";
				ss << "else\n";
				ss << "\techo \"Finished scanning as a regular user. Your LRFP environments may have been exposed. \"\n";
				ss << "fi\n\n";
				ss << "exit ${errorLevel}\n";
				if (this->outputPathTesterFilePath.empty())
				{
					std::cout << ss.str() << std::endl;
					this->flag |= 16/* 0b010000 */;
				}
				else
					try
					{
						std::ofstream outputPathTesterFile(this->outputPathTesterFilePath);
						if (outputPathTesterFile.is_open())
						{
							outputPathTesterFile << ss.str();
							outputPathTesterFile.close();
							this->flag |= 16/* 0b010000 */;
						}
					}
					catch (...) {}
			}
			return this->flag & 19/* 0b010011 */;
		}
		else
			return false;
	}
	bool generateTrickyStoreTarget()
	{
		if (this->flag & 3/* 0b000011 */)
		{
			this->flag &= 31/* 0b011111 */;
			if (!this->outputTargetFilePath.empty())
				this->flag |= 32/* 0b100000 */;
			else
			{
				std::set<std::string> targetPackageNames{};
				if (flagCG)
					for (const auto& item : this->j["C"]["G"])
						targetPackageNames.insert(item.get<std::string>());
				if (flagCZ)
					for (const auto& item : this->j["C"]["Z"])
						targetPackageNames.insert(item.get<std::string>());
				if (flagD)
					for (const auto& item : this->j["D"])
						targetPackageNames.insert(item.get<std::string>());
				if (flagM)
					for (const auto& item : this->j["M"])
						targetPackageNames.insert(item.get<std::string>());
				if (flagS)
					for (const auto& item : this->j["S"])
						targetPackageNames.insert(item.get<std::string>());
				if (flagT)
					for (const auto& item : this->j["T"])
					{
						const std::string packageName = item.get<std::string>();
						if (!packageName.empty())
						{
							if ('+' == packageName[0])
								targetPackageNames.insert(packageName.substr(1));
							else if ('-' == packageName[0])
								targetPackageNames.erase(packageName.substr(1));
						}
					}
				if ("." == this->outputTargetFilePath)
				{
					for (const std::string& packageName : targetPackageNames)
						std::cout << packageName << std::endl;
					this->flag |= 32/* 0b100000 */;
				}
				else
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
					}
					catch (...) {}
			}
			return this->flag & 35/* 0b100011 */;
		}
		else
			return false;
	}
	int getFlag() const
	{
		return this->flag;
	}
};



int main(int argc, char* argv[])
{
	Generator generator{};
	generator.parseArguments(argc, argv);
	generator.parseJSON();
	return generator.generateHMAConfigurations() && generator.generatePathTester() && generator.generateTrickyStoreTarget() ? EXIT_SUCCESS : EXIT_FAILURE;
}