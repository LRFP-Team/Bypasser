#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <filesystem>
#include "nlohmann/json.hpp" // https://github.com/nlohmann/json
constexpr const size_t DefaultMaximumCount = 10;


class Analyzer
{
private:
	inline static const std::string PackageName = "com.happyelements.AndroidAnimal";
	inline static const std::string ScoreFileName = "user_level_score.ds";
	std::vector<std::string> userFilePaths{};
	std::vector<std::string> scoreFilePaths{};
	
	static std::string escapeString(const std::string& s)
	{
		return nlohmann::json(s).dump();
	}
	static bool parseScoreFile(const std::string& filePath, std::map<int, long long int>& directory, std::string& message)
	{
		try
		{
			std::ifstream file(filePath);
			if (file.is_open())
			{
				nlohmann::json outerJson{};
				file >> outerJson;
				if (outerJson.contains("content") && outerJson["content"].is_string())
				{
					const nlohmann::json middleJson = nlohmann::json::parse(outerJson["content"].get<std::string>());
					if (middleJson.contains("levelRecord") && middleJson["levelRecord"].is_object())
					{
						const nlohmann::json& innerJson = middleJson["levelRecord"];
						for (nlohmann::json::const_iterator it = innerJson.begin(); it != innerJson.end(); ++it)
						{
							const int levelId = std::stoi(it.key());
							if (it.value().contains("levelScene") && "MAIN" == it.value()["levelScene"] && it.value().contains("updateTime") && it.value()["updateTime"].is_number_integer())
								directory[levelId] = it.value()["updateTime"].get<long long int>();
						}
						return true;
					}
					else
						message = "Cannot parse " + escapeString(filePath) + " without a \"levelRecord\" object field under the \"content\" field. ";
				}
				else
					message = "Cannot parse " + escapeString(filePath) + " without a \"content\" object field. ";
			}
			else
				message = "Failed to read " + escapeString(filePath) + " for parsing. ";
		}
		catch (const std::exception& e)
		{
			message = "Failed to parse " + escapeString(filePath) + " due to " + escapeString(e.what()) + ". ";
		}
		return false;
	}
	static std::map<int, long long int> checkTimeDeltas(const std::map<int, long long int>& dictionary, const size_t maximumCount)
	{
		std::map<int, long long int>::const_reverse_iterator previousIterator = dictionary.crbegin();
		std::map<int, long long int> levelTimeDeltas{};
		if (previousIterator != dictionary.crend())
		{
			std::map<int, long long int>::const_reverse_iterator currentIterator = previousIterator++;
			size_t count = 0;
			while (previousIterator != dictionary.crend() && previousIterator->first + 1 == currentIterator->first && count < maximumCount)
			{
				levelTimeDeltas[currentIterator->first] = currentIterator->second - previousIterator->second;
				++previousIterator;
				++currentIterator;
				++count;
			}
		}
		return levelTimeDeltas;
	}
	static std::string timestamp2string(long long int timestamp)
	{
		std::chrono::system_clock::time_point tp = std::chrono::system_clock::time_point(std::chrono::milliseconds(timestamp));
		std::time_t sec = std::chrono::system_clock::to_time_t(tp);
		std::tm tm_local = *std::localtime(&sec);
		std::stringstream ss;
		ss << std::put_time(&tm_local, "%Y-%m-%d %H:%M:%S");
		return ss.str();
	}
	
public:
	Analyzer()
	{
		
	}
	bool scanUsers(const std::string& basePath, const bool resetBeforeScanning, size_t& totalUserCount, size_t& addedUserCount)
	{
		if (resetBeforeScanning)
			this->userFilePaths.clear();
		const std::string absolutePath = std::filesystem::absolute(basePath).string();
		try
		{
			const size_t originalSize = this->userFilePaths.size();
			for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(absolutePath))
				if (!std::filesystem::is_symlink(entry.path()) && std::filesystem::is_directory(entry.path()) && std::find(this->userFilePaths.begin(), this->userFilePaths.end(), entry.path().string()) == this->userFilePaths.end())
					this->userFilePaths.push_back(entry.path().string());
			totalUserCount = this->userFilePaths.size();
			addedUserCount = totalUserCount - originalSize;
			std::cerr << "Successfully collected " << addedUserCount << " user(s) in " << escapeString(absolutePath) << " and " << totalUserCount << " in total. " << std::endl;
			return true;
		}
		catch (const std::exception& e)
		{
			std::cerr << "Failed to scan users in " << escapeString(absolutePath) << " due to " << escapeString(e.what()) << ". " << std::endl;
		}
		return false;
	}
	size_t scanUsers(size_t& totalUserCount, size_t& addedUserCount) { return this->scanUsers("/data/user", true, totalUserCount, addedUserCount); }
	size_t scanScores(const bool resetBeforeScanning, size_t& totalScoreCount, size_t& addedScoreCount)
	{
		size_t successCount = 0;
		if (this->userFilePaths.empty())
			std::cerr << "Please collect at least one user before scanning the score files. " << std::endl;
		else
		{
			if (this->userFilePaths.size() >= 2)
				std::cerr << "Scanning the score files in " << this->userFilePaths.size() << " user directories. " << std::endl;
			else
				std::cerr << "Scanning the score files in " << escapeString(this->userFilePaths[0]) << ". " << std::endl;
			if (resetBeforeScanning)
				this->scoreFilePaths.clear();
			const size_t originalCount = this->scoreFilePaths.size();
			for (const std::string& userFilePath : this->userFilePaths)
			{
				std::filesystem::path applicationDirectory = std::filesystem::path(userFilePath) / PackageName;
				try
				{
					size_t localSuccessCount = 0;
					if (!std::filesystem::is_symlink(applicationDirectory) && std::filesystem::is_directory(applicationDirectory))
					{
						for (const std::filesystem::directory_entry& entry : std::filesystem::recursive_directory_iterator(applicationDirectory))
							if (!std::filesystem::is_symlink(entry.path()) && std::filesystem::is_regular_file(entry.path()) && entry.path().filename() == ScoreFileName && std::find(this->scoreFilePaths.begin(), this->scoreFilePaths.end(), entry.path().string()) == this->scoreFilePaths.end())
							{
								this->scoreFilePaths.push_back(entry.path().string());
								++localSuccessCount;
							}
						++successCount;
						std::cerr << "- Successfully collected " << localSuccessCount << " score(s) in " << escapeString(userFilePath) << ". " << std::endl;
					}
					else
						std::cerr << "- Failed to scan scores in " << escapeString(userFilePath) << " as it is not a valid directory. " << std::endl;
				}
				catch (const std::exception& e)
				{
					std::cerr << "- Failed to scan scores in " << escapeString(userFilePath) << " due to " << escapeString(e.what()) << ". " << std::endl;
				}
			}
			totalScoreCount = this->scoreFilePaths.size();
			addedScoreCount = totalScoreCount - originalCount;
			if (this->userFilePaths.size() >= 2)
				std::cerr << (successCount == this->userFilePaths.size() ? "Successfully collected " : "Collected ") << addedScoreCount << " score(s) in " << this->userFilePaths.size() << " user directories and " << totalScoreCount << " in total. " << std::endl;
			else
				std::cerr << (successCount == this->userFilePaths.size() ? "Successfully collected " : "Collected ") << addedScoreCount << " score(s) in " << escapeString(this->userFilePaths[0]) << " and " << totalScoreCount << " in total. " << std::endl;
		}
		return successCount;
	}
	bool scanScores(size_t& totalScoreCount, size_t& addedScoreCount) { return this->scanScores(true, totalScoreCount, addedScoreCount); }
	bool analyze(const size_t maximumCount)
	{
		if (scoreFilePaths.empty())
		{
			std::cerr << "Please collect at least one score before analyzing. " << std::endl;
			return false;
		}
		else
		{
			size_t successCount = 0;
			for (const std::string& scoreFilePath : this->scoreFilePaths)
			{
				std::map<int, long long int> dictionary{};
				std::string message{};
				if (parseScoreFile(scoreFilePath, dictionary, message))
				{
					if (dictionary.size() >= 2)
					{
						std::map<int, long long int> timeDeltas = checkTimeDeltas(dictionary, maximumCount);
						if (timeDeltas.size() >= 1)
						{
							std::cout << "The most recent " << timeDeltas.size() << " time delta(s) from " << escapeString(scoreFilePath) << " are as follows. " << std::endl;
							for (std::map<int, long long int>::const_reverse_iterator it = timeDeltas.rbegin(); it != timeDeltas.rend(); ++it)
								std::cout << "- [" << it->first << " -> " << timestamp2string(dictionary[it->first]) << "] - [" << it->first - 1 << " -> " << timestamp2string(dictionary[it->first - 1]) << "] = " << it->second << " ms" << std::endl;
						}
						else
							std::cerr << "Skipped " << escapeString(scoreFilePath) << " due to inadequate time delta values. " << std::endl;
					}
					else
						std::cerr << "Skipped " << escapeString(scoreFilePath) << " due to inadequate main levels with the update time. " << std::endl;
					++successCount;
				}
				else
					std::cerr << message << std::endl;
			}
			return this->scoreFilePaths.size() == successCount;
		}
	}
};


int main(int argc, char* argv[])
{
	size_t maximumCount = DefaultMaximumCount;
	if (argc >= 2)
		try
		{
			maximumCount = static_cast<size_t>(std::stoull(argv[1]));
		}
		catch (...) {}
	if (maximumCount < 1)
		maximumCount = DefaultMaximumCount;
	Analyzer analyzer{};
	size_t totalUserCount = 0, addedUserCount = 0;
	if (analyzer.scanUsers(totalUserCount, addedUserCount) && totalUserCount >= 1)
	{
		std::cerr << std::endl;
		size_t totalScoreCount = 0, addedScoreCount = 0;
		if (analyzer.scanScores(totalScoreCount, addedScoreCount) && totalScoreCount >= 1)
		{
			std::cerr << std::endl;
			return analyzer.analyze(maximumCount) ? EXIT_SUCCESS : EXIT_FAILURE;
		}
		else
			return EOF;
	}
	else
		return EOF;
}