#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
class Ctr2Application
{
private:
	static constexpr const char* PackageName = "com.zeptolab.ctr2.f2p.google";
	static constexpr const char* PreferencesFileName = "CTR2.xml";

	enum class InputKind
	{
		User,
		Local,
		Network
	};

	enum class OutputKind
	{
		InPlace,
		Console,
		Directory,
		File,
		Network
	};

	struct Options
	{
		InputKind inputKind = InputKind::User;
		std::filesystem::path inputPath{};
		int userId = 0;
		OutputKind outputKind = OutputKind::InPlace;
		std::filesystem::path outputPath{};
		bool help = false;
		bool overwrite = false;
		std::optional<std::string> ssaid{};
		std::optional<int> coinCount{};
		std::optional<int> freeCoinCount{};
		std::optional<int> unlimitedCoinCount{};
		bool updateAll = false;
		bool updateCoin = false;
		bool updateFreeCoin = false;
		bool updateUnlimitedCoin = false;
	};

	struct LocatedPreferences
	{
		std::filesystem::path filePath{};
		std::filesystem::path packageDirectory{};
		int userId = 0;
		uid_t uid = 0;
	};

	struct SsaidLocation
	{
		std::filesystem::path filePath{};
		std::string settingName{};
	};

	struct FieldState
	{
		int count = 0;
		std::string hash{};
	};

	struct PreferencesState
	{
		FieldState coins{};
		FieldState freeCoins{};
		FieldState unlimitedCoins{};
	};

	struct TagRange
	{
		std::size_t begin = 0;
		std::size_t openEnd = 0;
		std::size_t end = 0;
	};

	std::string quote(const std::string& value)
	{
		return '"' + value + '"';
	}

	bool parseInteger(const std::string& text, int& value)
	{
		if (text.empty())
			return false;
		char* end = nullptr;
		errno = 0;
		const long long parsed = std::strtoll(text.c_str(), &end, 10);
		if (errno == ERANGE || end != text.c_str() + text.size()
			|| parsed < std::numeric_limits<int>::min() || parsed > std::numeric_limits<int>::max())
			return false;
		value = static_cast<int>(parsed);
		return true;
	}

	std::string lowercase(std::string value)
	{
		std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char character)
		{
			return static_cast<char>(std::tolower(character));
		});
		return value;
	}

	bool isAlias(const std::string& argument, const std::initializer_list<std::string_view> aliases)
	{
		const std::string normalized = lowercase(argument);
		return std::any_of(aliases.begin(), aliases.end(), [&](const std::string_view alias)
		{
			return normalized == alias;
		});
	}

	bool isHelpArgument(const std::string& argument)
	{
		return isAlias(argument, {"h", "/h", "-h", "help", "/help", "--help"});
	}

	void printHelp(const std::string& program)
	{
		std::cout
			<< "Usage: " << program << " [options]\n\n"
			<< "Input options:\n"
			<< "  -il, --input-local <local>          Read a local file or CTR2.xml in a local directory.\n"
			<< "  -in, --input-network <network>      Read a mounted network path.\n"
			<< "  -iu, --input-user <user>            Read CTR2.xml for an Android user ID.\n\n"
			<< "Output options:\n"
			<< "  -oc, --output-console               Write the XML document to standard output.\n"
			<< "  -od, --output-directory <directory> Write CTR2.xml to a local directory.\n"
			<< "  -of, --output-file <file>           Write to a local file.\n"
			<< "  -on, --output-network <network>     Write to a mounted network path.\n\n"
			<< "Modification options:\n"
			<< "  -s,  --ssaid <SSAID>                Change the SSAID.\n"
			<< "  -sc, --set-coin <coin>              Change the coin count.\n"
			<< "  -sf, --set-free-coin <free-coin>    Change the free coin count.\n"
			<< "  -su, --set-unlimited-coin <count>   Change the unlimited coin count.\n"
			<< "  -u,  --update-all                   Update all count hashes.\n"
			<< "  -uc, --update-coin                  Update the coin hash.\n"
			<< "  -uf, --update-free-coin             Update the free coin hash.\n"
			<< "  -uu, --update-unlimited-coin        Update the unlimited coin hash.\n\n"
			<< "Other options:\n"
			<< "  -h,  --help                         Show this help and exit successfully.\n"
			<< "  -y,  --yes                          Overwrite an existing output without asking.\n\n"
			<< "With no input option, Android user 0 is used. With no output option, the input file is overwritten.\n";
	}

	bool parseArguments(const int argc, char* argv[], Options& options)
	{
		for (int index = 1; index < argc; ++index)
		{
			if (isHelpArgument(argv[index]))
			{
				printHelp(argv[0]);
				options.help = true;
				return true;
			}
		}

		auto nextValue = [&](int& index, const std::string& argument) -> const char*
		{
			if (index + 1 >= argc)
			{
				std::cerr << "Missing value for argument: " << quote(argument) << "." << std::endl;
				return nullptr;
			}
			return argv[++index];
		};

		for (int index = 1; index < argc; ++index)
		{
			const std::string argument = argv[index];
			const char* value = nullptr;
			int parsed = 0;
			// Keep option recognition in lexicographical order.
			if (isAlias(argument, {"il", "/il", "-il", "input-local", "/input-local", "--input-local"}))
			{
				if (nullptr == (value = nextValue(index, argument))) return false;
				options.inputKind = InputKind::Local;
				options.inputPath = value;
				options.userId = 0;
			}
			else if (isAlias(argument, {"in", "/in", "-in", "input-network", "/input-network", "--input-network"}))
			{
				if (nullptr == (value = nextValue(index, argument))) return false;
				options.inputKind = InputKind::Network;
				options.inputPath = value;
				options.userId = 0;
			}
			else if (isAlias(argument, {"iu", "/iu", "-iu", "input-user", "/input-user", "--input-user"}))
			{
				if (nullptr == (value = nextValue(index, argument))) return false;
				if (!parseInteger(value, parsed) || parsed < 0)
				{
					std::cerr << "Invalid Android user ID: " << quote(value) << "." << std::endl;
					return false;
				}
				options.inputKind = InputKind::User;
				options.userId = parsed;
				options.inputPath.clear();
			}
			else if (isAlias(argument, {"oc", "/oc", "-oc", "output-console", "/output-console", "--output-console"}))
				options.outputKind = OutputKind::Console;
			else if (isAlias(argument, {"od", "/od", "-od", "output-directory", "/output-directory", "--output-directory"}))
			{
				if (nullptr == (value = nextValue(index, argument))) return false;
				options.outputKind = OutputKind::Directory;
				options.outputPath = value;
			}
			else if (isAlias(argument, {"of", "/of", "-of", "output-file", "/output-file", "--output-file"}))
			{
				if (nullptr == (value = nextValue(index, argument))) return false;
				options.outputKind = OutputKind::File;
				options.outputPath = value;
			}
			else if (isAlias(argument, {"on", "/on", "-on", "output-network", "/output-network", "--output-network"}))
			{
				if (nullptr == (value = nextValue(index, argument))) return false;
				options.outputKind = OutputKind::Network;
				options.outputPath = value;
			}
			else if (isAlias(argument, {"s", "/s", "-s", "ssaid", "/ssaid", "--ssaid"}))
			{
				if (nullptr == (value = nextValue(index, argument))) return false;
				options.ssaid = value;
			}
			else if (isAlias(argument, {"sc", "/sc", "-sc", "set-coin", "/set-coin", "--set-coin"}))
			{
				if (nullptr == (value = nextValue(index, argument))) return false;
				if (!parseInteger(value, parsed))
				{
					std::cerr << "Invalid coin count: " << quote(value) << "." << std::endl;
					return false;
				}
				options.coinCount = parsed;
			}
			else if (isAlias(argument, {"sf", "/sf", "-sf", "set-free-coin", "/set-free-coin", "--set-free-coin"}))
			{
				if (nullptr == (value = nextValue(index, argument))) return false;
				if (!parseInteger(value, parsed))
				{
					std::cerr << "Invalid free coin count: " << quote(value) << "." << std::endl;
					return false;
				}
				options.freeCoinCount = parsed;
			}
			else if (isAlias(argument, {"su", "/su", "-su", "set-unlimited-coin", "/set-unlimited-coin", "--set-unlimited-coin"}))
			{
				if (nullptr == (value = nextValue(index, argument))) return false;
				if (!parseInteger(value, parsed))
				{
					std::cerr << "Invalid unlimited coin count: " << quote(value) << "." << std::endl;
					return false;
				}
				options.unlimitedCoinCount = parsed;
			}
			else if (isAlias(argument, {"u", "/u", "-u", "ua", "/ua", "-ua", "update", "/update", "--update",
				"update-all", "/update-all", "--update-all"}))
				options.updateAll = true;
			else if (isAlias(argument, {"uc", "/uc", "-uc", "update-coin", "/update-coin", "--update-coin"}))
				options.updateCoin = true;
			else if (isAlias(argument, {"uf", "/uf", "-uf", "update-free-coin", "/update-free-coin", "--update-free-coin"}))
				options.updateFreeCoin = true;
			else if (isAlias(argument, {"uu", "/uu", "-uu", "update-unlimited-coin", "/update-unlimited-coin", "--update-unlimited-coin"}))
				options.updateUnlimitedCoin = true;
			else if (isAlias(argument, {"y", "/y", "-y", "yes", "/yes", "--yes"}))
				options.overwrite = true;
			else
			{
				std::cerr << "Unknown argument: " << quote(argument) << "." << std::endl;
				return false;
			}
		}
		return true;
	}

	bool isDecimal(const std::string& text)
	{
		return !text.empty() && std::all_of(text.begin(), text.end(), [](const unsigned char character) { return std::isdigit(character); });
	}

	bool locatePackageForUser(const int userId, LocatedPreferences& located)
	{
		std::error_code error{};
		const std::filesystem::path packageDirectory = std::filesystem::path("/data/user")
			/ std::to_string(userId) / PackageName;
		if (!std::filesystem::is_directory(packageDirectory, error))
		{
			std::cerr << "The Cut the Rope 2 is not installed for Android user " << userId << "." << std::endl;
			return false;
		}
		struct stat information{};
		if (0 != stat(packageDirectory.c_str(), &information))
		{
			std::cerr << "Failed to read from " << quote(packageDirectory.string()) << "." << std::endl;
			return false;
		}
		located.packageDirectory = packageDirectory;
		located.userId = userId;
		located.uid = information.st_uid;
		return true;
	}

	bool resolveInputPath(const std::filesystem::path& supplied, std::filesystem::path& resolved)
	{
		std::error_code error{};
		resolved = std::filesystem::canonical(supplied, error);
		if (error)
		{
			std::cerr << "Failed to read from " << quote(supplied.string()) << "." << std::endl;
			return false;
		}
		if (std::filesystem::is_directory(resolved, error))
		{
			resolved = std::filesystem::canonical(resolved / PreferencesFileName, error);
			if (error)
			{
				std::cerr << "Failed to read from " << quote((supplied / PreferencesFileName).string()) << "." << std::endl;
				return false;
			}
		}
		if (!std::filesystem::is_regular_file(resolved, error) || error)
		{
			std::cerr << "Failed to read from " << quote(resolved.string()) << "." << std::endl;
			return false;
		}
		return true;
	}

	bool locatePreferences(const Options& options, LocatedPreferences& located)
	{
		if (!locatePackageForUser(options.userId, located))
			return false;
		if (InputKind::User == options.inputKind)
		{
			located.filePath = located.packageDirectory / "shared_prefs" / PreferencesFileName;
			std::error_code error{};
			if (!std::filesystem::is_regular_file(located.filePath, error))
			{
				std::cerr << "Failed to read from " << quote(located.filePath.string()) << "." << std::endl;
				return false;
			}
			return true;
		}
		return resolveInputPath(options.inputPath, located.filePath);
	}

	bool readFile(const std::filesystem::path& path, std::string& contents)
	{
		std::ifstream stream(path, std::ios::binary);
		if (!stream)
			return false;
		std::ostringstream buffer{};
		buffer << stream.rdbuf();
		if (stream.bad())
			return false;
		contents = buffer.str();
		return true;
	}

	std::filesystem::path absolutePath(const std::filesystem::path& path)
	{
		std::error_code error{};
		const std::filesystem::path absolute = std::filesystem::absolute(path, error);
		return error ? path : absolute.lexically_normal();
	}

	bool confirmOverwrite(const std::filesystem::path& path)
	{
		std::cerr << "The output file " << quote(path.string()) << " already exists. Overwrite it? [y/N] ";
		std::string answer{};
		if (!std::getline(std::cin, answer))
			return false;
		answer = lowercase(answer);
		return "y" == answer || "yes" == answer;
	}

	bool prepareOutput(const Options& options, const LocatedPreferences& located,
		std::optional<std::filesystem::path>& outputPath)
	{
		if (OutputKind::Console == options.outputKind)
		{
			outputPath.reset();
			return true;
		}
		if (OutputKind::InPlace == options.outputKind)
		{
			outputPath = located.filePath;
			return true;
		}

		std::filesystem::path target = options.outputPath;
		std::error_code error{};
		if (OutputKind::Directory == options.outputKind)
		{
			std::filesystem::create_directories(target, error);
			if (error || !std::filesystem::is_directory(target, error))
			{
				std::cerr << "Failed to create directory " << quote(target.string()) << "." << std::endl;
				return false;
			}
			target /= PreferencesFileName;
		}
		else
		{
			const std::filesystem::path parent = target.parent_path();
			if (!parent.empty() && !std::filesystem::is_directory(parent, error))
			{
				std::cerr << "The output directory does not exist: " << quote(parent.string()) << "." << std::endl;
				return false;
			}
		}

		target = absolutePath(target);
		error.clear();
		const bool exists = std::filesystem::exists(target, error);
		if (error)
		{
			std::cerr << "Failed to access " << quote(target.string()) << "." << std::endl;
			return false;
		}
		if (exists && !options.overwrite && !confirmOverwrite(target))
		{
			std::cerr << "The output file was not overwritten." << std::endl;
			return false;
		}
		outputPath = target;
		return true;
	}

	std::optional<std::string> attributeValue(const std::string& document, const std::size_t begin,
		const std::size_t end, const std::string& attribute)
	{
		std::size_t position = begin;
		while (position < end)
		{
			position = document.find(attribute, position);
			if (std::string::npos == position || position >= end)
				return std::nullopt;
			const bool leftBoundary = position == begin
				|| !(std::isalnum(static_cast<unsigned char>(document[position - 1])) || '_' == document[position - 1]);
			const std::size_t afterName = position + attribute.size();
			const bool rightBoundary = afterName >= end
				|| !(std::isalnum(static_cast<unsigned char>(document[afterName])) || '_' == document[afterName]);
			if (!leftBoundary || !rightBoundary)
			{
				position = afterName;
				continue;
			}
			std::size_t cursor = afterName;
			while (cursor < end && std::isspace(static_cast<unsigned char>(document[cursor])))
				++cursor;
			if (cursor >= end || '=' != document[cursor++])
			{
				position = afterName;
				continue;
			}
			while (cursor < end && std::isspace(static_cast<unsigned char>(document[cursor])))
				++cursor;
			if (cursor >= end || ('"' != document[cursor] && '\'' != document[cursor]))
				return std::nullopt;
			const char delimiter = document[cursor++];
			const std::size_t valueEnd = document.find(delimiter, cursor);
			if (std::string::npos == valueEnd || valueEnd > end)
				return std::nullopt;
			return document.substr(cursor, valueEnd - cursor);
		}
		return std::nullopt;
	}

	std::optional<TagRange> findTag(const std::string& document, const std::string& element,
		const std::string& key)
	{
		const std::string prefix = '<' + element;
		std::size_t position = 0;
		while (std::string::npos != (position = document.find(prefix, position)))
		{
			const std::size_t afterElement = position + prefix.size();
			if (afterElement < document.size()
				&& !std::isspace(static_cast<unsigned char>(document[afterElement])) && '>' != document[afterElement])
			{
				position = afterElement;
				continue;
			}
			const std::size_t openEnd = document.find('>', afterElement);
			if (std::string::npos == openEnd)
				return std::nullopt;
			const std::optional<std::string> name = attributeValue(document, afterElement, openEnd, "name");
			if (name.has_value() && *name == key)
			{
				std::size_t end = openEnd + 1;
				if ("string" == element)
				{
					const std::string closing = "</" + element + '>';
					const std::size_t closingPosition = document.find(closing, openEnd + 1);
					if (std::string::npos == closingPosition)
						return std::nullopt;
					end = closingPosition + closing.size();
				}
				return TagRange{position, openEnd, end};
			}
			position = openEnd + 1;
		}
		return std::nullopt;
	}

	bool readCount(const std::string& document, const std::string& key, int& value)
	{
		const std::optional<TagRange> tag = findTag(document, "int", key);
		if (!tag.has_value())
		{
			value = 0;
			return true;
		}
		const std::optional<std::string> text = attributeValue(document, tag->begin, tag->openEnd, "value");
		return text.has_value() && parseInteger(*text, value);
	}

	bool readHash(const std::string& document, const std::string& key, std::string& value)
	{
		const std::optional<TagRange> tag = findTag(document, "string", key);
		if (!tag.has_value())
			return false;
		const std::size_t closing = document.find("</string>", tag->openEnd + 1);
		if (std::string::npos == closing)
			return false;
		value = document.substr(tag->openEnd + 1, closing - tag->openEnd - 1);
		return true;
	}

	bool readState(const std::string& document, PreferencesState& state)
	{
		return readCount(document, "com.zeptolab.ctr2.f2p.coins", state.coins.count)
			&& readHash(document, "com.zeptolab.ctr2.f2p.coins_HASH", state.coins.hash)
			&& readCount(document, "com.zeptolab.ctr2.f2p.coins_free", state.freeCoins.count)
			&& readHash(document, "com.zeptolab.ctr2.f2p.coins_free_HASH", state.freeCoins.hash)
			&& readCount(document, "com.zeptolab.ctr2.f2p.coins_unlim", state.unlimitedCoins.count)
			&& readHash(document, "com.zeptolab.ctr2.f2p.coins_unlim_HASH", state.unlimitedCoins.hash);
	}

	bool setCount(std::string& document, const std::string& key, const int value)
	{
		const std::optional<TagRange> tag = findTag(document, "int", key);
		if (!tag.has_value())
		{
			const std::size_t mapEnd = document.rfind("</map>");
			if (std::string::npos == mapEnd)
				return false;
			const std::string addition = "    <int name=\"" + key + "\" value=\"" + std::to_string(value) + "\" />\n";
			document.insert(mapEnd, addition);
			return true;
		}

		std::size_t position = document.find("value", tag->begin);
		if (std::string::npos == position || position >= tag->openEnd)
			return false;
		position = document.find('=', position + 5);
		if (std::string::npos == position || position >= tag->openEnd)
			return false;
		++position;
		while (position < tag->openEnd && std::isspace(static_cast<unsigned char>(document[position])))
			++position;
		if (position >= tag->openEnd || ('"' != document[position] && '\'' != document[position]))
			return false;
		const char delimiter = document[position++];
		const std::size_t valueEnd = document.find(delimiter, position);
		if (std::string::npos == valueEnd || valueEnd > tag->openEnd)
			return false;
		document.replace(position, valueEnd - position, std::to_string(value));
		return true;
	}

	bool setHash(std::string& document, const std::string& key, const std::string& value)
	{
		const std::optional<TagRange> tag = findTag(document, "string", key);
		if (!tag.has_value())
			return false;
		const std::size_t closing = document.find("</string>", tag->openEnd + 1);
		if (std::string::npos == closing)
			return false;
		document.replace(tag->openEnd + 1, closing - tag->openEnd - 1, value);
		return true;
	}

	std::optional<std::string> readTextSetting(const std::string& document, const std::string& name)
	{
		std::size_t position = 0;
		while (std::string::npos != (position = document.find("<setting", position)))
		{
			const std::size_t end = document.find('>', position + 8);
			if (std::string::npos == end)
				return std::nullopt;
			const std::optional<std::string> settingName = attributeValue(document, position + 8, end, "name");
			if (settingName.has_value() && *settingName == name)
				return attributeValue(document, position + 8, end, "value");
			position = end + 1;
		}
		return std::nullopt;
	}

	std::string escapeXmlAttribute(const std::string& value)
	{
		std::string escaped{};
		escaped.reserve(value.size());
		for (const char character : value)
		{
			switch (character)
			{
			case '&': escaped += "&amp;"; break;
			case '<': escaped += "&lt;"; break;
			case '>': escaped += "&gt;"; break;
			case '"': escaped += "&quot;"; break;
			case '\'': escaped += "&apos;"; break;
			default: escaped += character; break;
			}
		}
		return escaped;
	}

	bool replaceAttributeValue(std::string& document, const std::size_t begin, const std::size_t end,
		const std::string& attribute, const std::string& value)
	{
		std::size_t position = begin;
		while (position < end)
		{
			position = document.find(attribute, position);
			if (std::string::npos == position || position >= end)
				return false;
			const bool leftBoundary = position == begin
				|| !(std::isalnum(static_cast<unsigned char>(document[position - 1])) || '_' == document[position - 1]);
			const std::size_t afterName = position + attribute.size();
			const bool rightBoundary = afterName >= end
				|| !(std::isalnum(static_cast<unsigned char>(document[afterName])) || '_' == document[afterName]);
			if (!leftBoundary || !rightBoundary)
			{
				position = afterName;
				continue;
			}
			std::size_t cursor = afterName;
			while (cursor < end && std::isspace(static_cast<unsigned char>(document[cursor])))
				++cursor;
			if (cursor >= end || '=' != document[cursor++])
			{
				position = afterName;
				continue;
			}
			while (cursor < end && std::isspace(static_cast<unsigned char>(document[cursor])))
				++cursor;
			if (cursor >= end || ('"' != document[cursor] && '\'' != document[cursor]))
				return false;
			const char delimiter = document[cursor++];
			const std::size_t valueEnd = document.find(delimiter, cursor);
			if (std::string::npos == valueEnd || valueEnd > end)
				return false;
			document.replace(cursor, valueEnd - cursor, value);
			return true;
		}
		return false;
	}

	bool setTextSetting(std::string& document, const std::string& name, const std::string& value)
	{
		std::size_t position = 0;
		while (std::string::npos != (position = document.find("<setting", position)))
		{
			const std::size_t end = document.find('>', position + 8);
			if (std::string::npos == end)
				return false;
			const std::optional<std::string> settingName = attributeValue(document, position + 8, end, "name");
			if (settingName.has_value() && *settingName == name)
				return replaceAttributeValue(document, position + 8, end, "value", escapeXmlAttribute(value));
			position = end + 1;
		}
		return false;
	}

	class AbxReader
	{
	private:
		static constexpr std::uint8_t Attribute = 15;
		static constexpr std::uint8_t StartTag = 2;
		static constexpr std::uint8_t EndTag = 3;
		static constexpr std::uint8_t TypeNull = 1U << 4U;
		static constexpr std::uint8_t TypeString = 2U << 4U;
		static constexpr std::uint8_t TypeStringInterned = 3U << 4U;
		static constexpr std::uint8_t TypeBytesHex = 4U << 4U;
		static constexpr std::uint8_t TypeBytesBase64 = 5U << 4U;
		static constexpr std::uint8_t TypeInt = 6U << 4U;
		static constexpr std::uint8_t TypeIntHex = 7U << 4U;
		static constexpr std::uint8_t TypeLong = 8U << 4U;
		static constexpr std::uint8_t TypeLongHex = 9U << 4U;
		static constexpr std::uint8_t TypeFloat = 10U << 4U;
		static constexpr std::uint8_t TypeDouble = 11U << 4U;
		static constexpr std::uint8_t TypeBooleanTrue = 12U << 4U;
		static constexpr std::uint8_t TypeBooleanFalse = 13U << 4U;

		std::string_view data_{};
		std::size_t position_ = 4;
		std::vector<std::string> internedStrings_{};

		bool skip(const std::size_t count)
		{
			if (count > data_.size() - position_)
				return false;
			position_ += count;
			return true;
		}

		bool readByte(std::uint8_t& value)
		{
			if (position_ >= data_.size())
				return false;
			value = static_cast<std::uint8_t>(data_[position_++]);
			return true;
		}

		bool readUnsignedShort(std::uint16_t& value)
		{
			if (2 > data_.size() - position_)
				return false;
			value = (static_cast<std::uint16_t>(static_cast<unsigned char>(data_[position_])) << 8U)
				| static_cast<std::uint16_t>(static_cast<unsigned char>(data_[position_ + 1]));
			position_ += 2;
			return true;
		}

		bool readUnsignedInt(std::uint32_t& value)
		{
			if (4 > data_.size() - position_)
				return false;
			value = 0;
			for (std::size_t index = 0; index < 4; ++index)
				value = (value << 8U) | static_cast<unsigned char>(data_[position_ + index]);
			position_ += 4;
			return true;
		}

		bool readUnsignedLong(std::uint64_t& value)
		{
			if (8 > data_.size() - position_)
				return false;
			value = 0;
			for (std::size_t index = 0; index < 8; ++index)
				value = (value << 8U) | static_cast<unsigned char>(data_[position_ + index]);
			position_ += 8;
			return true;
		}

		bool readUtf(std::string& value)
		{
			std::uint16_t length = 0;
			if (!readUnsignedShort(length) || length > data_.size() - position_)
				return false;
			value.assign(data_.substr(position_, length));
			position_ += length;
			return true;
		}

		bool readInternedUtf(std::string& value)
		{
			std::uint16_t reference = 0;
			if (!readUnsignedShort(reference))
				return false;
			if (0xffffU == reference)
			{
				if (!readUtf(value))
					return false;
				internedStrings_.push_back(value);
				return true;
			}
			if (reference >= internedStrings_.size())
				return false;
			value = internedStrings_[reference];
			return true;
		}

		bool readValue(const std::uint8_t type, std::string& value, bool& isString)
		{
			isString = false;
			value.clear();
			if (TypeNull == type)
				return true;
			if (TypeString == type)
			{
				isString = readUtf(value);
				return isString;
			}
			if (TypeStringInterned == type)
			{
				isString = readInternedUtf(value);
				return isString;
			}
			if (TypeBytesHex == type || TypeBytesBase64 == type)
			{
				std::uint16_t length = 0;
				return readUnsignedShort(length) && skip(length);
			}
			if (TypeInt == type || TypeIntHex == type || TypeFloat == type)
			{
				std::uint32_t number = 0;
				if (!readUnsignedInt(number))
					return false;
				if (TypeFloat != type)
				{
					value = std::to_string(static_cast<std::int32_t>(number));
					isString = true;
				}
				return true;
			}
			if (TypeLong == type || TypeLongHex == type || TypeDouble == type)
			{
				std::uint64_t number = 0;
				if (!readUnsignedLong(number))
					return false;
				if (TypeDouble != type)
				{
					value = std::to_string(static_cast<std::int64_t>(number));
					isString = true;
				}
				return true;
			}
			if (TypeBooleanTrue == type || TypeBooleanFalse == type)
			{
				value = TypeBooleanTrue == type ? "true" : "false";
				isString = true;
				return true;
			}
			return false;
		}

	public:
		struct ValueLocation
		{
			std::size_t tokenPosition = 0;
			std::size_t valueBegin = 0;
			std::size_t valueEnd = 0;
			bool interned = false;
			bool newInterned = false;
		};

		explicit AbxReader(const std::string& document) : data_(document) {}

		std::optional<std::string> findSetting(const std::string& requestedName)
		{
			if (data_.size() < 4 || data_.substr(0, 4) != std::string_view("ABX\0", 4))
				return std::nullopt;

			std::string currentTag{};
			std::optional<std::string> settingName{};
			std::optional<std::string> settingValue{};
			while (position_ < data_.size())
			{
				std::uint8_t token = 0;
				if (!readByte(token))
					return std::nullopt;
				const std::uint8_t event = token & 0x0fU;
				const std::uint8_t type = token & 0xf0U;

				if (Attribute == event)
				{
					std::string attributeName{};
					std::string attributeValue{};
					bool hasTextValue = false;
					if (!readInternedUtf(attributeName) || !readValue(type, attributeValue, hasTextValue))
						return std::nullopt;
					if ("setting" == currentTag && hasTextValue)
					{
						if ("name" == attributeName)
							settingName = attributeValue;
						else if ("value" == attributeName)
							settingValue = attributeValue;
						if (settingName.has_value() && *settingName == requestedName && settingValue.has_value())
							return settingValue;
					}
					continue;
				}

				std::string eventValue{};
				bool hasTextValue = false;
				if (!readValue(type, eventValue, hasTextValue))
					return std::nullopt;
				if (StartTag == event)
				{
					if (!hasTextValue)
						return std::nullopt;
					currentTag = eventValue;
					settingName.reset();
					settingValue.reset();
				}
				else if (EndTag == event)
				{
					currentTag.clear();
					settingName.reset();
					settingValue.reset();
				}
			}
			return std::nullopt;
		}

		std::optional<ValueLocation> findSettingValueLocation(const std::string& requestedName)
		{
			if (data_.size() < 4 || data_.substr(0, 4) != std::string_view("ABX\0", 4))
				return std::nullopt;

			std::string currentTag{};
			std::optional<std::string> settingName{};
			std::optional<ValueLocation> settingValueLocation{};
			while (position_ < data_.size())
			{
				const std::size_t tokenPosition = position_;
				std::uint8_t token = 0;
				if (!readByte(token))
					return std::nullopt;
				const std::uint8_t event = token & 0x0fU;
				const std::uint8_t type = token & 0xf0U;

				if (Attribute == event)
				{
					std::string attributeName{};
					std::string attributeValue{};
					bool hasTextValue = false;
					if (!readInternedUtf(attributeName))
						return std::nullopt;
					const std::size_t valueBegin = position_;
					if (!readValue(type, attributeValue, hasTextValue))
						return std::nullopt;
					const std::size_t valueEnd = position_;
					if ("setting" == currentTag && hasTextValue)
					{
						if ("name" == attributeName)
							settingName = attributeValue;
						else if ("value" == attributeName && (TypeString == type || TypeStringInterned == type))
						{
							const bool newInterned = TypeStringInterned == type && valueEnd >= valueBegin + 2
								&& 0xffU == static_cast<unsigned char>(data_[valueBegin])
								&& 0xffU == static_cast<unsigned char>(data_[valueBegin + 1]);
							settingValueLocation = ValueLocation{tokenPosition, valueBegin, valueEnd,
								TypeStringInterned == type, newInterned};
						}
						if (settingName.has_value() && *settingName == requestedName && settingValueLocation.has_value())
							return settingValueLocation;
					}
					continue;
				}

				std::string eventValue{};
				bool hasTextValue = false;
				if (!readValue(type, eventValue, hasTextValue))
					return std::nullopt;
				if (StartTag == event)
				{
					if (!hasTextValue)
						return std::nullopt;
					currentTag = eventValue;
					settingName.reset();
					settingValueLocation.reset();
				}
				else if (EndTag == event)
				{
					currentTag.clear();
					settingName.reset();
					settingValueLocation.reset();
				}
			}
			return std::nullopt;
		}
	};

	std::optional<std::string> readSetting(const std::string& document, const std::string& name)
	{
		if (document.size() >= 4 && 0 == std::memcmp(document.data(), "ABX\0", 4))
			return AbxReader(document).findSetting(name);
		return readTextSetting(document, name);
	}

	bool setAbxSetting(std::string& document, const std::string& name, const std::string& value)
	{
		if (value.size() > std::numeric_limits<std::uint16_t>::max())
			return false;
		const std::optional<AbxReader::ValueLocation> location = AbxReader(document).findSettingValueLocation(name);
		if (!location.has_value())
			return false;

		std::string encoded{};
		if (location->interned && location->newInterned)
		{
			encoded.push_back(static_cast<char>(0xff));
			encoded.push_back(static_cast<char>(0xff));
		}
		else if (location->interned)
		{
			document[location->tokenPosition] = static_cast<char>((static_cast<unsigned char>(document[location->tokenPosition]) & 0x0fU) | 0x20U);
		}
		encoded.push_back(static_cast<char>((value.size() >> 8U) & 0xffU));
		encoded.push_back(static_cast<char>(value.size() & 0xffU));
		encoded += value;
		document.replace(location->valueBegin, location->valueEnd - location->valueBegin, encoded);
		return true;
	}

	bool setSetting(std::string& document, const std::string& name, const std::string& value)
	{
		if (document.size() >= 4 && 0 == std::memcmp(document.data(), "ABX\0", 4))
			return setAbxSetting(document, name, value);
		return setTextSetting(document, name, value);
	}

	bool obtainSsaid(const LocatedPreferences& located, std::string& ssaid, SsaidLocation& location)
	{
		const std::filesystem::path userDirectory = std::filesystem::path("/data/system/users") / std::to_string(located.userId);
		const std::filesystem::path ssaidPath = userDirectory / "settings_ssaid.xml";
		std::string document{};
		if (readFile(ssaidPath, document))
		{
			const std::optional<std::string> value = readSetting(document, std::to_string(located.uid));
			if (value.has_value() && !value->empty())
			{
				ssaid = *value;
				location.filePath = ssaidPath;
				location.settingName = std::to_string(located.uid);
				return true;
			}
		}

		const std::filesystem::path securePath = userDirectory / "settings_secure.xml";
		if (readFile(securePath, document))
		{
			const std::optional<std::string> value = readSetting(document, "android_id");
			if (value.has_value() && !value->empty())
			{
				ssaid = *value;
				location.filePath = securePath;
				location.settingName = "android_id";
				return true;
			}
		}

		std::cerr << "Failed to obtain the SSAID for " << quote(PackageName) << "." << std::endl;
		return false;
	}

	class Md5
	{
	private:
		std::array<std::uint32_t, 4> state_{0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U};
		std::array<std::uint8_t, 64> buffer_{};
		std::uint64_t size_ = 0;
		std::size_t buffered_ = 0;

		static std::uint32_t rotateLeft(const std::uint32_t value, const std::uint32_t shift)
		{
			return (value << shift) | (value >> (32U - shift));
		}

		void transform(const std::uint8_t block[64])
		{
			static constexpr std::array<std::uint32_t, 64> shifts{
				7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
				5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
				4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
				6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
			};
			static constexpr std::array<std::uint32_t, 64> constants{
				0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU, 0xf57c0fafU, 0x4787c62aU, 0xa8304613U, 0xfd469501U,
				0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU, 0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U,
				0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU, 0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
				0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU, 0xa9e3e905U, 0xfcefa3f8U, 0x676f02d9U, 0x8d2a4c8aU,
				0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU, 0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
				0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U, 0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
				0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U, 0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU, 0x85845dd1U,
				0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U, 0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U
			};

			std::array<std::uint32_t, 16> words{};
			for (std::size_t index = 0; index < words.size(); ++index)
				words[index] = static_cast<std::uint32_t>(block[index * 4])
					| (static_cast<std::uint32_t>(block[index * 4 + 1]) << 8U)
					| (static_cast<std::uint32_t>(block[index * 4 + 2]) << 16U)
					| (static_cast<std::uint32_t>(block[index * 4 + 3]) << 24U);

			std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
			for (std::uint32_t index = 0; index < 64; ++index)
			{
				std::uint32_t function = 0, wordIndex = 0;
				if (index < 16)
				{
					function = (b & c) | (~b & d);
					wordIndex = index;
				}
				else if (index < 32)
				{
					function = (d & b) | (~d & c);
					wordIndex = (5U * index + 1U) % 16U;
				}
				else if (index < 48)
				{
					function = b ^ c ^ d;
					wordIndex = (3U * index + 5U) % 16U;
				}
				else
				{
					function = c ^ (b | ~d);
					wordIndex = (7U * index) % 16U;
				}
				const std::uint32_t previousD = d;
				d = c;
				c = b;
				b += rotateLeft(a + function + constants[index] + words[wordIndex], shifts[index]);
				a = previousD;
			}
			state_[0] += a;
			state_[1] += b;
			state_[2] += c;
			state_[3] += d;
		}

	public:
		void update(const std::uint8_t* data, std::size_t length)
		{
			size_ += length;
			while (length > 0)
			{
				const std::size_t copied = std::min(length, buffer_.size() - buffered_);
				std::memcpy(buffer_.data() + buffered_, data, copied);
				buffered_ += copied;
				data += copied;
				length -= copied;
				if (buffered_ == buffer_.size())
				{
					transform(buffer_.data());
					buffered_ = 0;
				}
			}
		}

		std::array<std::uint8_t, 16> finish()
		{
			const std::uint64_t bitLength = size_ * 8U;
			const std::uint8_t marker = 0x80U;
			update(&marker, 1);
			const std::uint8_t zero = 0;
			while (56 != buffered_)
				update(&zero, 1);
			std::array<std::uint8_t, 8> encodedLength{};
			for (std::size_t index = 0; index < encodedLength.size(); ++index)
				encodedLength[index] = static_cast<std::uint8_t>((bitLength >> (index * 8U)) & 0xffU);
			update(encodedLength.data(), encodedLength.size());

			std::array<std::uint8_t, 16> digest{};
			for (std::size_t index = 0; index < state_.size(); ++index)
				for (std::size_t byte = 0; byte < 4; ++byte)
					digest[index * 4 + byte] = static_cast<std::uint8_t>((state_[index] >> (byte * 8U)) & 0xffU);
			return digest;
		}
	};

	std::string md5(const std::string& input)
	{
		Md5 digest{};
		digest.update(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
		const std::array<std::uint8_t, 16> bytes = digest.finish();
		std::ostringstream result{};
		result << std::hex << std::setfill('0');
		for (const std::uint8_t byte : bytes)
			result << std::setw(2) << static_cast<unsigned int>(byte);
		return result.str();
	}

	std::string countHash(const std::string& ssaid, const std::string& logicalKey, const int count)
	{
		const std::string decimal = std::to_string(count);
		return md5(decimal + "!don'thackthis!" + logicalKey + '!' + decimal + '!' + ssaid + "!ctr2.");
	}

	bool writeFileLocked(const std::filesystem::path& path, const std::string& contents)
	{
		const int descriptor = open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0666);
		if (descriptor < 0)
			return false;
		bool successful = 0 == flock(descriptor, LOCK_EX);
		if (successful)
			successful = 0 == lseek(descriptor, 0, SEEK_SET);
		std::size_t written = 0;
		while (successful && written < contents.size())
		{
			const ssize_t result = write(descriptor, contents.data() + written, contents.size() - written);
			if (result < 0 && EINTR == errno)
				continue;
			if (result <= 0)
				successful = false;
			else
				written += static_cast<std::size_t>(result);
		}
		if (successful)
			successful = 0 == ftruncate(descriptor, static_cast<off_t>(contents.size()));
		if (successful)
			successful = 0 == fsync(descriptor);
		flock(descriptor, LOCK_UN);
		if (0 != close(descriptor))
			successful = false;
		return successful;
	}

	bool updateStoredSsaid(const SsaidLocation& location, const std::string& ssaid)
	{
		std::string document{};
		if (!readFile(location.filePath, document) || !setSetting(document, location.settingName, ssaid)
			|| !writeFileLocked(location.filePath, document))
			return false;
		std::string verifiedDocument{};
		if (!readFile(location.filePath, verifiedDocument))
			return false;
		const std::optional<std::string> verified = readSetting(verifiedDocument, location.settingName);
		return verified.has_value() && *verified == ssaid;
	}

	bool shouldUpdateCoinHash(const Options& options, const bool ssaidChanged)
	{
		return ssaidChanged || options.updateAll || options.updateCoin || options.coinCount.has_value();
	}

	bool shouldUpdateFreeCoinHash(const Options& options, const bool ssaidChanged)
	{
		return ssaidChanged || options.updateAll || options.updateFreeCoin || options.freeCoinCount.has_value();
	}

	bool shouldUpdateUnlimitedCoinHash(const Options& options, const bool ssaidChanged)
	{
		return ssaidChanged || options.updateAll || options.updateUnlimitedCoin || options.unlimitedCoinCount.has_value();
	}

	bool applyRequestedChanges(std::string& document, const PreferencesState& before, const Options& options,
		const std::string& ssaid, const bool ssaidChanged)
	{
		auto apply = [&](const FieldState& field, const std::optional<int>& requested,
			const bool updateHash, const std::string& countKey, const std::string& hashKey,
			const std::string& logicalKey)
		{
			const int targetCount = requested.value_or(field.count);
			if (requested.has_value() && !setCount(document, countKey, targetCount))
				return false;
			return !updateHash || setHash(document, hashKey, countHash(ssaid, logicalKey, targetCount));
		};
		return apply(before.coins, options.coinCount, shouldUpdateCoinHash(options, ssaidChanged),
			"com.zeptolab.ctr2.f2p.coins", "com.zeptolab.ctr2.f2p.coins_HASH", "f2p.coins")
			&& apply(before.freeCoins, options.freeCoinCount, shouldUpdateFreeCoinHash(options, ssaidChanged),
				"com.zeptolab.ctr2.f2p.coins_free", "com.zeptolab.ctr2.f2p.coins_free_HASH", "f2p.coins_free")
			&& apply(before.unlimitedCoins, options.unlimitedCoinCount,
				shouldUpdateUnlimitedCoinHash(options, ssaidChanged),
				"com.zeptolab.ctr2.f2p.coins_unlim", "com.zeptolab.ctr2.f2p.coins_unlim_HASH", "f2p.coins_unlim");
	}

	bool fieldMatches(const FieldState& actual, const FieldState& before, const std::optional<int>& requested,
		const std::string& ssaid, const std::string& logicalKey, const bool updateHash)
	{
		const int targetCount = requested.value_or(before.count);
		const bool countMatches = !requested.has_value() || actual.count == targetCount;
		const bool hashMatches = !updateHash || actual.hash == countHash(ssaid, logicalKey, targetCount);
		return countMatches && hashMatches;
	}

	void printField(const std::string& label, const std::string& logicalKey,
		const FieldState& before, const FieldState& after, const std::optional<int>& requested,
		const std::string& originalSsaid, const std::string& effectiveSsaid,
		const bool updateHash, const bool attempted)
	{
		const int targetCount = requested.value_or(before.count);
		const std::string expectedBeforeHash = countHash(originalSsaid, logicalKey, before.count);
		const std::string targetHash = countHash(effectiveSsaid, logicalKey, targetCount);
		const std::string expectedSuffix = before.hash == expectedBeforeHash
			? std::string() : " (expected: " + expectedBeforeHash + ')';

		if (requested.has_value())
		{
			const bool successful = attempted && after.count == targetCount;
			std::cerr << label << " count: " << before.count << " -> " << targetCount << " -> "
				<< (successful ? "successful" : "failed") << std::endl;
		}
		else
			std::cerr << label << " count: " << before.count << std::endl;

		if (updateHash)
		{
			const bool successful = attempted && after.hash == targetHash;
			std::cerr << label << " count hash: " << before.hash << expectedSuffix << " -> " << targetHash << " -> "
				<< (successful ? "successful" : "failed") << std::endl;
		}
		else
			std::cerr << label << " count hash: " << before.hash << expectedSuffix << std::endl;
	}

	void printState(const std::filesystem::path& inputPath,
		const std::optional<std::filesystem::path>& outputPath,
		const std::string& originalSsaid, const std::string& effectiveSsaid,
		const PreferencesState& before, const PreferencesState& after, const Options& options,
		const bool ssaidUpdateSuccessful, const bool ssaidChanged, const bool attempted)
	{
		std::cerr << "Input: " << inputPath.string() << std::endl;
		if (outputPath.has_value())
			std::cerr << "Output: " << outputPath->string() << std::endl;
		if (options.ssaid.has_value())
			std::cerr << "SSAID: " << originalSsaid << " -> " << *options.ssaid << " -> "
				<< (ssaidUpdateSuccessful ? "reboot required" : "failed") << std::endl;
		else
			std::cerr << "SSAID: " << originalSsaid << std::endl;
		printField("Coin", "f2p.coins", before.coins, after.coins, options.coinCount,
			originalSsaid, effectiveSsaid, shouldUpdateCoinHash(options, ssaidChanged), attempted);
		printField("Free coin", "f2p.coins_free", before.freeCoins, after.freeCoins, options.freeCoinCount,
			originalSsaid, effectiveSsaid, shouldUpdateFreeCoinHash(options, ssaidChanged), attempted);
		printField("Unlimited coin", "f2p.coins_unlim", before.unlimitedCoins, after.unlimitedCoins,
			options.unlimitedCoinCount, originalSsaid, effectiveSsaid,
			shouldUpdateUnlimitedCoinHash(options, ssaidChanged), attempted);
	}

public:
	int run(int argc, char* argv[])
	{
		Options options{};
		if (!parseArguments(argc, argv, options))
			return EXIT_FAILURE;
		if (options.help)
			return EXIT_SUCCESS;
		if (0 != geteuid())
		{
			std::cerr << "Permission denied, are you root?" << std::endl;
			return EXIT_FAILURE;
		}

		LocatedPreferences located{};
		if (!locatePreferences(options, located))
			return EXIT_FAILURE;
		std::optional<std::filesystem::path> outputPath{};
		if (!prepareOutput(options, located, outputPath))
			return EXIT_FAILURE;

		std::string originalSsaid{};
		SsaidLocation ssaidLocation{};
		if (!obtainSsaid(located, originalSsaid, ssaidLocation))
			return EXIT_FAILURE;

		std::string document{};
		if (!readFile(located.filePath, document))
		{
			std::cerr << "Failed to read from " << quote(located.filePath.string()) << "." << std::endl;
			return EXIT_FAILURE;
		}
		PreferencesState before{};
		if (!readState(document, before))
		{
			std::cerr << "Failed to read the required fields from " << quote(located.filePath.string()) << "." << std::endl;
			return EXIT_FAILURE;
		}

		std::string effectiveSsaid = originalSsaid;
		bool ssaidUpdateSuccessful = true;
		bool ssaidChanged = false;
		if (options.ssaid.has_value() && *options.ssaid != originalSsaid)
		{
			ssaidUpdateSuccessful = updateStoredSsaid(ssaidLocation, *options.ssaid);
			if (ssaidUpdateSuccessful)
			{
				effectiveSsaid = *options.ssaid;
				ssaidChanged = true;
			}
			else
				std::cerr << "Failed to write to " << quote(ssaidLocation.filePath.string()) << "." << std::endl;
		}

		PreferencesState after = before;
		const bool gameChangesRequested = ssaidChanged || options.coinCount.has_value()
			|| options.freeCoinCount.has_value() || options.unlimitedCoinCount.has_value()
			|| options.updateAll || options.updateCoin || options.updateFreeCoin || options.updateUnlimitedCoin;
		const bool outputCopyRequested = OutputKind::InPlace != options.outputKind;
		bool gameUpdateSuccessful = true;
		if (gameChangesRequested || outputCopyRequested)
		{
			std::string modifiedDocument = document;
			gameUpdateSuccessful = applyRequestedChanges(modifiedDocument, before, options,
				effectiveSsaid, ssaidChanged);
			if (gameUpdateSuccessful && OutputKind::Console == options.outputKind)
			{
				std::cout.write(modifiedDocument.data(), static_cast<std::streamsize>(modifiedDocument.size()));
				std::cout.flush();
				gameUpdateSuccessful = std::cout.good() && readState(modifiedDocument, after);
			}
			else if (gameUpdateSuccessful && outputPath.has_value())
			{
				gameUpdateSuccessful = writeFileLocked(*outputPath, modifiedDocument);
				std::string verifiedDocument{};
				if (gameUpdateSuccessful)
					gameUpdateSuccessful = readFile(*outputPath, verifiedDocument) && readState(verifiedDocument, after);
			}
			if (gameUpdateSuccessful)
				gameUpdateSuccessful = fieldMatches(after.coins, before.coins, options.coinCount,
					effectiveSsaid, "f2p.coins", shouldUpdateCoinHash(options, ssaidChanged))
					&& fieldMatches(after.freeCoins, before.freeCoins, options.freeCoinCount,
						effectiveSsaid, "f2p.coins_free", shouldUpdateFreeCoinHash(options, ssaidChanged))
					&& fieldMatches(after.unlimitedCoins, before.unlimitedCoins, options.unlimitedCoinCount,
						effectiveSsaid, "f2p.coins_unlim", shouldUpdateUnlimitedCoinHash(options, ssaidChanged));
			if (!gameUpdateSuccessful)
			{
				if (OutputKind::Console == options.outputKind)
					std::cerr << "Failed to write the XML document to standard output." << std::endl;
				else
					std::cerr << "Failed to write to " << quote(outputPath->string()) << "." << std::endl;
			}
		}

		printState(located.filePath, outputPath, originalSsaid, effectiveSsaid, before, after, options,
			ssaidUpdateSuccessful, ssaidChanged, gameUpdateSuccessful);
		return ssaidUpdateSuccessful && gameUpdateSuccessful ? EXIT_SUCCESS : EXIT_FAILURE;
	}
};
}

int main(int argc, char* argv[])
{
	Ctr2Application application{};
	return application.run(argc, argv);
}
