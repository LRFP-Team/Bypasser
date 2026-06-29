#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <filesystem>
#include <chrono>
#include "nlohmann/json.hpp" // https://github.com/nlohmann/json
constexpr const size_t DefaultMaximumCount = 10;


class Analyzer
{
private:
	inline static const std::string PackageName = "com.happyelements.AndroidAnimal";
	inline static const std::string ScoreFileName = "user_level_score.ds";
	std::vector<std::string> userFilePaths{};
	std::vector<std::string> scoreFilePaths{};
	
	static int getDigit(const char character, const int radix)
	{
		if ('0' <= character && character <= '9')
		{
			const int digit = character - '0';
			return digit < radix ? digit : EOF;
		}
		else if ('A' <= character && character <= 'Z')
		{
			const int digit = character - 'A' + 10;
			return digit < radix ? digit : EOF;
		}
		else if ('a' <= character && character <= 'z')
		{
			const int digit = character - 'a' + 10;
			return digit < radix ? digit : EOF;
		}
		else
			return EOF;
	}
	static std::string escapeString(const std::string& s)
	{
		return nlohmann::json(s).dump(-1, '\t', true);
	}
	static bool parseScoreFile(const std::string& filePath, std::vector<std::pair<int, long long int>>& dictionary, std::string& message)
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
							long double longDoubleValue = 0;
							int levelID = 0;
							if (
								it.value().contains("levelScene") && "MAIN" == it.value()["levelScene"] && it.value().contains("updateTime")
								&& it.value()["updateTime"].is_number_integer() && parseRealNumber(it.key(), longDoubleValue, levelID) && levelID >= 1
							)
								dictionary.emplace_back(levelID, it.value()["updateTime"].get<long long int>());
						}
						std::sort(dictionary.begin(), dictionary.end(), [](const std::pair<int, long long int>& a, const std::pair<int, long long int>& b) { return a.second > b.second; });
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
	static bool parseRealNumber(const std::string& s, long double& longDoubleValue, int& intValue, unsigned char& flag)
	{
		std::string realNumberString{};
		for (const char& character : s)
			if ('+' == character || '-' == character || '.' == character || ('0' <= character && character <= '9') || ('a' <= character && character <= 'z'))
				realNumberString += character;
			else if ('A' <= character && character <= 'Z')
				realNumberString += character | 32/* 0b00100000 */;
		if (realNumberString.find('x') == std::string::npos && realNumberString.find('e') != std::string::npos && !realNumberString.empty() && realNumberString.back() != 'e')
			try
			{
				std::size_t _ = 0;
				longDoubleValue = std::stold(realNumberString, &_);
				flag = 64/* 0b01000000 */;
				return true;
			}
			catch (...)
			{
				return false;
			}
		else if (realNumberString.empty())
		{
			intValue = 0;
			flag = 16/* 0b00010000 */;
			return true;
		}
		else
		{
			size_t frontIndex = 0, endIndex = realNumberString.length() - 1;
			bool isNegative = false, isRegular = true;
			for (bool breakFlag = false; frontIndex < realNumberString.length(); ++frontIndex)
			{
				switch (realNumberString[frontIndex])
				{
				case '\t':
				case ' ':
				case '+':
				case '_':
					continue;
				case '-':
					isNegative = !isNegative;
					break;
				default:
					breakFlag = true;
					break;
				}
				if (breakFlag)
					break;
			}
			flag = isNegative ? 32/* 0b00100000 */ : 0/* 0b00000000 */;
			int radix = 0;
			for (bool breakFlag = false; frontIndex < realNumberString.length(); ++frontIndex) // make ``frontIndex`` point to the first effective digit
			{
				switch (realNumberString[frontIndex])
				{
				case '0':
					continue;
				case 'x':
					radix = 16;
					++frontIndex;
					breakFlag = true;
					break;
				case 'd':
					radix = 10;
					++frontIndex;
					breakFlag = true;
					break;
				case 'o':
					radix = 8;
					++frontIndex;
					breakFlag = true;
					break;
				case 'q':
					radix = 4;
					++frontIndex;
					breakFlag = true;
					break;
				case 'b':
					radix = 2;
					++frontIndex;
					breakFlag = true;
					break;
				default:
					breakFlag = true;
					break;
				}
				if (breakFlag)
					break;
			}
			if (0 == radix) // prefix is prior to suffix
				for (bool breakFlag = false; endIndex > frontIndex; --endIndex) // make ``endIndex`` point to the first effective digit
				{
					switch (realNumberString[endIndex])
					{
					case 'x':
						radix = 16;
						--endIndex;
						breakFlag = true;
						break;
					case 'd':
						radix = 10;
						--endIndex;
						breakFlag = true;
						break;
					case 'o':
						radix = 8;
						--endIndex;
						breakFlag = true;
						break;
					case 'q':
						radix = 4;
						--endIndex;
						breakFlag = true;
						break;
					case 'b':
						radix = 2;
						--endIndex;
						breakFlag = true;
						break;
					default:
						breakFlag = true;
						break;
					}
					if (breakFlag)
						break;
				}
			if (endIndex - frontIndex == 2)
			{
				const std::string subString = realNumberString.substr(frontIndex, 3);
				if ("inf" == subString)
				{
					longDoubleValue = isNegative ? -std::numeric_limits<double>::infinity() : std::numeric_limits<double>::infinity();
					isRegular = false;
				}
				else if ("nan" == subString)
					isRegular = false;
			}
			if (isRegular)
			{
				flag |= 16/* 0b00010000 */;
				if (0 == radix)
					radix = 10;
				bool containingMultipleRadixPoints = false, isDecimal = false, isIllegalDigitDetected = false, isOverflowed = false;
				long double decimalValue = 0;
				int integerValue = 0;
				for (size_t index = frontIndex; index <= endIndex; ++index)
					if ('.' == realNumberString[index])
					{
						frontIndex = ++index;
						for (; index <= endIndex; ++index) // locate the second radix point
							if ('.' == realNumberString[index])
							{
								containingMultipleRadixPoints = true;
								endIndex = index - 1;
								break;
							}
						while (endIndex > frontIndex)
							if ('0' == realNumberString[endIndex])
								--endIndex;
							else
								break;
						for (index = endIndex; index >= frontIndex; --index)
						{
							const int digit = getDigit(realNumberString[index], radix);
							if (0 <= digit && digit < radix)
							{
								decimalValue += digit;
								decimalValue /= radix;
								isDecimal = true;
							}
							else
								isIllegalDigitDetected = true;
						}
						break;
					}
					else
					{
						const int digit = getDigit(realNumberString[index], radix);
						if (0 <= digit && digit < radix)
						{
							const long long int testValue = static_cast<long long int>(integerValue) * radix + digit; // test whether it is overflowed
							if (testValue > std::numeric_limits<int>::max())
							{
								integerValue = std::numeric_limits<int>::max(); // this line can be commented out
								isOverflowed = true;
								break;
							}
							else
								integerValue = static_cast<int>(testValue);
						}
						else
							isIllegalDigitDetected = true;
					}
				if (containingMultipleRadixPoints)
					flag |= 8/* 0b00001000 */;
				if (isDecimal)
				{
					flag |= 4/* 0b00000100 */;
					if (isOverflowed)
					{
						longDoubleValue = isNegative ? -std::numeric_limits<double>::infinity() : std::numeric_limits<double>::infinity();
						flag |= 1/* 0b00000001 */;
					}
					else
						longDoubleValue = isNegative ? -(decimalValue + integerValue) : decimalValue + integerValue;
				}
				else if (isOverflowed)
				{
					intValue =  isNegative ? std::numeric_limits<int>::min() : std::numeric_limits<int>::max();
					flag |= 1/* 0b00000001 */;
				}
				else
					intValue = isNegative ? -integerValue : integerValue;
				if (isIllegalDigitDetected)
					flag |= 2/* 0b00000010 */;
			}
			return true;
		}
	}
	static bool parseRealNumber(const std::string& s, long double& longDoubleValue, int& intValue) { unsigned char flag = 0; return parseRealNumber(s, longDoubleValue, intValue, flag); }
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
				std::vector<std::pair<int, long long int>> dictionary{};
				std::string message{};
				if (parseScoreFile(scoreFilePath, dictionary, message))
				{
					if (dictionary.size() >= 1)
					{
						std::cout << "The most recent " << std::min(dictionary.size(), maximumCount) << " time delta(s) from " << escapeString(scoreFilePath) << " are as follows. " << std::endl;
						std::vector<std::pair<int, long long int>>::const_iterator previousIterator = dictionary.cbegin();
						std::vector<std::pair<int, long long int>>::const_iterator currentIterator = previousIterator++;
						const long long int currentTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
						std::cout << "- [* -> " << timestamp2string(currentTimestamp) << "] - [" << previousIterator->first << " -> " << timestamp2string(previousIterator->second) << "] = " << (currentTimestamp  - previousIterator->second) << " ms" << std::endl;
						size_t deltaCount = 0;
						while (currentIterator != dictionary.cend() && deltaCount < maximumCount)
						{
							std::cout << "- [" << currentIterator->first << " -> " << timestamp2string(currentIterator->second) << "] - [" << previousIterator->first << " -> " << timestamp2string(previousIterator->second) << "] = " << (currentIterator->second  - previousIterator->second) << " ms" << std::endl;
							++previousIterator;
							++currentIterator;
							++deltaCount;
						}
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
	long double longDoubleValue = 0;
	int intValue = 0;
	if (argc >= 2 && Analyzer::parseRealNumber(argv[1], longDoubleValue, intValue))
		maximumCount = static_cast<size_t>(intValue);
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