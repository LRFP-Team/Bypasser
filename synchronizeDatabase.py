import os
from sys import exit
from codecs import lookup
from collections import OrderedDict
from datetime import datetime
from getpass import getpass
from hashlib import sha512
from json import dump, loads
from re import compile
from subprocess import TimeoutExpired, run
from time import time_ns
from zipfile import ZipFile, ZipInfo
try:
	os.chdir(os.path.abspath(os.path.dirname(__file__)))
except:
	pass
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EOF = (-1)


class DatabaseManager:
	__DefaultDatabaseFilePath = "database.json"
	__DefaultTimeout = 10
	__DefaultEncoding = "utf-8"
	__Pattern = compile("^[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+$")
	__Caches = {}
	__MajorVersion = 3
	def __init__(self:object, databaseFilePath:str = __DefaultDatabaseFilePath, timeout:int = __DefaultTimeout, encoding:str = __DefaultEncoding) -> object:
		self.__databaseFilePath = databaseFilePath if isinstance(databaseFilePath, str) else DatabaseManager.__DefaultDatabaseFilePath
		self.__timeout = timeout if isinstance(timeout, int) and timeout >= 1 else DatabaseManager.__DefaultTimeout
		try:
			lookup(encoding)
			self.__encoding = encoding
		except:
			self.__encoding = DatabaseManager.__DefaultEncoding
		self.__database = None
	def __getVersionString(self:object) -> str:
		if isinstance(self.__database, dict):
			stack, keyCounts = [(value, 1) for value in reversed(self.__database.values())], [DatabaseManager.__MajorVersion, len(self.__database)]
			while stack:
				element, level = stack.pop()
				if isinstance(element, dict):
					level += 1
					while len(keyCounts) <= level:
						keyCounts.append(0)
					keyCounts[level] += len(element)
					stack.extend((child, level) for child in reversed(element.values()))
			timestamp = time_ns()
			return "{0}+HKT{1}{2:09d}".format(".".join(str(keyCount) for keyCount in keyCounts), datetime.fromtimestamp(timestamp // 1000000000).strftime("%Y%m%d%H%M%S"), timestamp % 1000000000)
		else:
			return str(DatabaseManager.__MajorVersion)
	def load(self:object) -> tuple:
		try:
			with open(self.__databaseFilePath, "r", encoding = self.__encoding) as f:
				self.__database = loads(f.read())
			if isinstance(self.__database, dict):
				initializedKeys, removedKeyCounts, removedValueCount = set(), {}, 0
				
				# First-level #
				for key in tuple(self.__database.keys()):
					if not (
						(key in ("C", "N", "T") and isinstance(self.__database[key], dict))
						or (key in ("D", "M", "S") and isinstance(self.__database[key], list))
						or (key in ("U", "V") and isinstance(self.__database[key], str))
					):
						del self.__database[key]
						removedKeyCounts.setdefault(0, 0)
						removedKeyCounts[0] += 1
				
				# Second-level #
				if "C" in self.__database and isinstance(self.__database["C"], dict):
					if "" in self.__database["C"] and isinstance(self.__database["C"][""], list):
						for i in range(len(self.__database["C"][""]) - 1, -1, -1):
							if not (isinstance(self.__database["C"][""][i], str) and DatabaseManager.__Pattern.match(self.__database["C"][""][i])):
								del self.__database["C"][""][i]
								removedValueCount += 1
					else:
						self.__database["C"][""] = []
						initializedKeys.add("C ")
					if "_" in self.__database["C"] and isinstance(self.__database["C"]["_"], dict):
						for key in tuple(self.__database["C"]["_"].keys()):
							if isinstance(key, str) and len(key) == 1 and 'A' <= key <= 'Z' and isinstance(self.__database["C"]["_"][key], list):
								for i in range(len(self.__database["C"]["_"][key]) - 1, -1, -1):
									if not (isinstance(self.__database["C"]["_"][key][i], str) and DatabaseManager.__Pattern.match(self.__database["C"]["_"][key][i])):
										del self.__database["C"]["_"][key][i]
										removedValueCount += 1
							else:
								del self.__database["C"]["_"][key]
								removedKeyCounts.setdefault(2, 0)
								removedKeyCounts[2] += 1
					else:
						self.__database["C"]["_"] = {}
						initializedKeys.add("C_")
					for key in tuple(self.__database["C"].keys()):
						if isinstance(key, str):
							if len(key) == 1 and 'A' <= key <= 'Z' and isinstance(self.__database["C"][key], list):
								# Compatible with Version 3.6.x ($C_X$) #
								self.__database["C"]["_"].setdefault(key, [])
								for value in self.__database["C"][key]:
									if isinstance(value, str) and DatabaseManager.__Pattern.match(value):
										self.__database["C"]["_"][key].append(value)
									else:
										removedValueCount += 1
								del self.__database["C"][key]
							elif DatabaseManager.__Pattern.match(key):
								# Compatible with Version 3.6.x ($C$) #
								self.__database["C"][""].append(key)
								del self.__database["C"][key]
							elif key not in ("", "_"):
								del self.__database["C"][key]
								removedKeyCounts.setdefault(1, 0)
								removedKeyCounts[1] += 1
						else:
							del self.__database["C"][key]
							removedKeyCounts.setdefault(1, 0)
							removedKeyCounts[1] += 1
					self.__database["C"][""].sort()
					for i in range(len(self.__database["C"][""]) - 1, 0, -1):
						if self.__database["C"][""][i - 1] == self.__database["C"][""][i]:
							del self.__database["C"][""][i]
					for key in self.__database["C"]["_"].keys():
						self.__database["C"]["_"][key].sort()
						for i in range(len(self.__database["C"]["_"][key]) - 1, 0, -1):
							if self.__database["C"]["_"][key][i - 1] == self.__database["C"]["_"][key][i]:
								del self.__database["C"]["_"][key][i]
				else:
					self.__database["C"] = {"":[], "_":{}}
					initializedKeys.add("C")
				if "D" in self.__database and isinstance(self.__database["D"], list):
					for i in range(len(self.__database["D"]) - 1, -1, -1):
						if not (isinstance(self.__database["D"][i], str) and DatabaseManager.__Pattern.match(self.__database["D"][i])):
							del self.__database["D"][i]
							removedValueCount += 1
					self.__database["D"].sort()
					for i in range(len(self.__database["D"]) - 1, 0, -1):
						if self.__database["D"][i - 1] == self.__database["D"][i]:
							del self.__database["D"][i]
				else:
					self.__database["D"] = []
					initializedKeys.add("D")
				if "M" in self.__database and isinstance(self.__database["M"], list):
					for i in range(len(self.__database["M"]) - 1, -1, -1):
						if not (isinstance(self.__database["M"][i], str) and DatabaseManager.__Pattern.match(self.__database["M"][i])):
							del self.__database["M"][i]
							removedValueCount += 1
					self.__database["M"].sort()
					for i in range(len(self.__database["M"]) - 1, 0, -1):
						if self.__database["M"][i - 1] == self.__database["M"][i]:
							del self.__database["M"][i]
				else:
					self.__database["M"] = []
					initializedKeys.add("M")
				if "N" in self.__database and isinstance(self.__database["N"], dict):
					for key, value in tuple(self.__database["N"].items()):
						if isinstance(key, str) and DatabaseManager.__Pattern.match(key) and isinstance(value, dict):
							for subKey, subValue in tuple(value.items()):
								if not (isinstance(subKey, str) and DatabaseManager.__Pattern.match(subKey) and isinstance(subValue, bool)):
									del self.__database["N"][key][subKey]
									removedValueCount += 1
						else:
							del self.__database["N"][key]
							removedValueCount += 1
				else:
					self.__database["N"] = {}
					initializedKeys.add("N")
				if "S" in self.__database and isinstance(self.__database["S"], list):
					for i in range(len(self.__database["S"]) - 1, -1, -1):
						if not (isinstance(self.__database["S"][i], str) and DatabaseManager.__Pattern.match(self.__database["S"][i])):
							del self.__database["S"][i]
							removedValueCount += 1
					self.__database["S"].sort()
					for i in range(len(self.__database["S"]) - 1, 0, -1):
						if self.__database["S"][i - 1] == self.__database["S"][i]:
							del self.__database["S"][i]
				else:
					self.__database["S"] = []
					initializedKeys.add("S")
				if "T" in self.__database and isinstance(self.__database["T"], dict):
					for key, value in tuple(self.__database["T"].items()):
						if not (isinstance(key, str) and DatabaseManager.__Pattern.match(key) and isinstance(value, bool)):
							del self.__database["T"][key]
							removedValueCount += 1
				else:
					self.__database["T"] = {}
					initializedKeys.add("T")
				if not ("U" in self.__database and isinstance(self.__database["U"], str)):
					self.__database["U"] = DatabaseManager.__Pattern.pattern
					initializedKeys.add("U")
				if not ("V" in self.__database and isinstance(self.__database["V"], str)):
					self.__database["V"] = self.__getVersionString()
					initializedKeys.add("V")
				return (True, (initializedKeys, removedKeyCounts, removedValueCount))
			else:
				self.__database = None
				return (False, ValueError("The data loaded from {0} could not be recognized. ".format(repr(self.__databaseFilePath))))
		except BaseException as e:
			return (False, e)
	def check(self:object) -> tuple:
		if isinstance(self.__database, dict):
			orderedDict, d = OrderedDict(), OrderedDict()
			if "C" in self.__database and isinstance(self.__database["C"], dict)):
				if "" in self.__database["C"] and isinstance(self.__database["C"][""], (tuple, list, set)):
					orderedDict["C"] = set(self.__database["C"][""])
				if "_" in self.__database["C"] and isinstance(self.__database["C"]["_"], dict):
					for key in self.__database["C"]["_"].keys():
						if isinstance(key, str) and isinstance(self.__database["C"]["_"][key], (tuple, list, set)):
							orderedDict["C" + key] = set(self.__database["C"]["_"][key])
			if "D" in self.__database and isinstance(self.__database["D"], (tuple, list, set)):
				orderedDict["D"] = set(self.__database["D"])
			if "M" in self.__database and isinstance(self.__database["M"], (tuple, list, set)):
				orderedDict["M"] = set(self.__database["M"])
			if "S" in self.__database and isinstance(self.__database["S"], (tuple, list, set)):
				orderedDict["S"] = set(self.__database["S"])
			keys = tuple(orderedDict.keys())
			keyLength = len(keys)
			for i in range(keyLength - 1):
				for j in range(i + 1, keyLength):
					intersection = orderedDict[keys[i]] & orderedDict[keys[j]]
					if intersection:
						d[("${0}$".format(keys[i]), "${0}$".format(keys[j]))] = intersection
			return (not d, d)
		else:
			return (False, TypeError("The database is not a ``dict``. Please check whether the method function ``load`` has been called. "))
	def __fetchPackageNamesFromURL(self:object, URL:str, d:dict) -> set:
		packageNames = set()
		if isinstance(URL, str) and isinstance(d, dict):
			if URL not in DatabaseManager.__Caches:
				r = __import__("requests").get(URL, timeout = self.__timeout)
				if 200 == r.status_code:
					DatabaseManager.__Caches[URL] = r.content
				else:
					d[URL] = r.status_code
			if URL in DatabaseManager.__Caches:
				obj = loads(DatabaseManager.__Caches[URL])
				if isinstance(obj, list):
					for item in obj:
						if isinstance(item, dict) and "name" in item and DatabaseManager.__Pattern.match(item["name"]):
							packageNames.add(item["name"])
				elif isinstance(obj, dict) and "$D$" in obj and isinstance(obj["$D$"], list):
					for item in obj["$D$"]:
						if (
							isinstance(item, dict) and "packageName" in item and "category" in item and len(item["category"]) <= 5
							and item["category"].startswith("$D") and item["category"].endswith("$")
						):
							if isinstance(item["packageName"], (tuple, list, set)):
								for packageName in item["packageName"]:
									if DatabaseManager.__Pattern.match(packageName):
										packageNames.add(packageName)
							elif isinstance(item["packageName"], str) and DatabaseManager.__Pattern.match(item["packageName"]):
								packageNames.add(item["packageName"])
		return packageNames
	def updateFromURLs(self:object, URLs:tuple|list|set|str, key:str, incrementalUpdate:bool = True) -> tuple:
		try:
			if isinstance(self.__database, dict) and key in ("D", "M"):
				stack, packageNames, d, originalSize = [URLs], set(), OrderedDict(), 0
				while stack:
					element = stack.pop()
					if isinstance(element, (tuple, list, set)):
						stack.extend(reversed(element))
					elif isinstance(element, str):
						try:
							packageNames.update(self.__fetchPackageNamesFromURL(element, d))
						except BaseException as e:
							d[element] = e
				if key in self.__database and isinstance(self.__database[key], (tuple, list, set)) and (not isinstance(incrementalUpdate, bool) or incrementalUpdate):
					originalSize = len(self.__database[key])
					packageNames.update(self.__database[key])
				self.__database[key] = sorted(list(packageNames))
				return (True, len(self.__database[key]) - originalSize, d)
			else:
				return (False, 0, KeyError("The database was not initialized or the condition ``key in (\"D\", \"M\")`` was not satisfied. "))
		except BaseException as e:
			return (False, 0, e)
	def save(self:object) -> tuple:
		if isinstance(self.__database, dict):
			self.__database["V"] = self.__getVersionString()
			try:
				with open(self.__databaseFilePath, "w", encoding = self.__encoding) as f:
					dump(self.__database, f, indent = "\t", ensure_ascii = False, sort_keys = True)
				return (True, None)
			except BaseException as e:
				return (False, e)
		else:
			return (False, TypeError("The database is not a ``dict``. Please check whether the method function ``load`` has been called. "))


class RegularUpdater:
	__DefaultTimeout = 10
	__PositiveAnswers = ("Y", "YES", "1", "T", "TRUE")
	def __init__(self:object, srcFolderPath:str, webrootName:str, databaseFileName:str, actionAFileName:str, actionBFileName:str) -> object: # -> 0b00000001
		try:
			# Parameters #
			self.__srcFolderPath = srcFolderPath
			self.__webrootName = webrootName
			self.__databaseFileName = databaseFileName
			self.__actionAFileName = actionAFileName
			self.__actionBFileName = actionBFileName
			
			# Initialization #
			self.__webrootFolderPath = os.path.join(self.__srcFolderPath, self.__webrootName)
			self.__databaseFilePath = os.path.join(self.__webrootFolderPath, self.__databaseFileName)
			self.__webrootFilePath = os.path.join(self.__srcFolderPath, self.__webrootName + ".zip")
			self.__actionAFilePath = os.path.join(self.__srcFolderPath, self.__actionAFileName)
			self.__actionBFilePath = os.path.join(self.__srcFolderPath, self.__actionBFileName)
			
			# Main #
			self.__databaseManager = DatabaseManager(databaseFilePath = self.__databaseFilePath)
			self.__flag = 0b00000001
			print("Successfully initialized the updater with the parameters passed. ")
		except BaseException as e:
			self.__flag = 0b00000000
			print("Failed to initialize the updater with the parameters passed. ")
	def gitPull(self:object) -> bool: # 0b00000001 + 0b00000001 -> 0b00000010
		if self.__flag & 0b00000011 >= 1:
			self.__flag = self.__flag & 0b00000000 | 0b00000001
			print("Pulling from the remote repository. ")
			try:
				result = run(("git", "pull"), timeout = RegularUpdater.__DefaultTimeout)
				if EXIT_SUCCESS == result.returncode:
					self.__flag += 0b00000001
					print("Successfully pulled from the remote repository. ")
					return True
				else:
					print("Failed to pull from the remote repository. ")
					return False
			except TimeoutExpired as e:
				print("Failed tp pull from the remote repository due to {0}. ".format({"cmd":e.cmd, "timeout":e.timeout}))
			except BaseException as e:
				print("Failed tp pull from the remote repository due to {0}. ".format(repr(e)))
		else:
			print("Please initialize the updater before pulling. ")
		return False
	def setPermissions(self:object) -> bool: # (0b00000010 | 0b00000011 -> 0b00000011, 0b01111111 + 0b01000000 -> 0b10111111)
		if (
			self.__flag & 0b00100000 and self.__flag & 0b00010000 and self.__flag & 0b00001000 and self.__flag & 0b00000100
			and self.__flag & 0b00000010 and self.__flag & 0b00000001 and self.__flag >> 6 >= 1
		):
			self.__flag = self.__flag & 0b00111111 | 0b01000000
		elif self.__flag & 0b00000011 >= 2:
			self.__flag = self.__flag & 0b00000000 | 0b00000010
		else:
			print("Please pull from the remote repository before setting permissions. ")
			return False
		baseExceptions = []
		try:
			os.chmod(".", 0o755)
			for root, folderNames, fileNames in os.walk("."):
				for folderName in folderNames:
					folderPath = os.path.join(root, folderName)
					try:
						os.chmod(folderPath, 0o755)
					except BaseException as innerBaseException:
						baseExceptions.append((folderPath, 0o755, innerBaseException))
				for fileName in fileNames:
					filePath = os.path.join(root, fileName)
					if "LICENSE" == fileName or os.path.splitext(fileName)[1] == ".sha512":
						try:
							os.chmod(filePath, 0o444)
						except BaseException as innerBaseException:
							baseExceptions.append((filePath, 0o444, innerBaseException))
					elif "build.sh" == fileName:
						try:
							os.chmod(filePath, 0o744)
						except BaseException as innerBaseException:
							baseExceptions.append((filePath, 0o744, innerBaseException))
					else:
						try:
							os.chmod(filePath, 0o644)
						except BaseException as innerBaseException:
							baseExceptions.append((filePath, 0o644, innerBaseException))
		except BaseException as outerBaseException:
			baseExceptions.append((".", 0o755, outerBaseException))
		if baseExceptions:
			print("Failed to set permissions due to the following base exception(s). ")
			for filePath, permission, baseException in baseExceptions:
				print("{0} -> {1} -> {2}".format(repr(filePath), oct(permission), repr(baseException)))
			return False
		else:
			if (
				self.__flag & 0b00100000 and self.__flag & 0b00010000 and self.__flag & 0b00001000 and self.__flag & 0b00000100
				and self.__flag & 0b00000010 and self.__flag & 0b00000001 and self.__flag >> 6 >= 1
			):
				self.__flag += 0b01000000
			elif self.__flag & 0b00000011 >= 2:
				self.__flag |= 0b00000011
			print("Successfully set permissions. ")
			return True
	def loadDatabase(self:object) -> bool: # 0b00?00011 + 0b00000100 -> 0b00?00111
		if self.__flag & 0b00000010 and self.__flag & 0b00000001:
			self.__flag &= 0b00100011
			validity, information = self.__databaseManager.load()
			if validity:
				if any(information[0]) or information[1] or information[2]:
					keys, values = tuple(zip(*sorted(information[1].items()))) if information[1] else ((), ())
					print("Loaded {0} with {1} key(s) initialized, {2} key(s) removed for Layer(s) {3}, and {4} value(s) removed in total. ".format(
						repr(self.__databaseFilePath), information[0], values, keys, information[2])
					)
				else:
					self.__flag += 0b00000100
					print("Successfully loaded the database from {0}. ".format(repr(self.__databaseFilePath)))
					return True
			else:
				print("Failed to load {0} due to {1}. ".format(repr(self.__databaseFilePath), repr(information)))
		else:
			print("Please initialize the updater and set permissions before loading the database. ")
		return False
	def checkDatabase(self:object) -> bool: # (0b00?00111, 0b00?01111) + 0b00000100 -> (0b00?01011, 0b00?10011)
		if self.__flag & 0b00000010 and self.__flag & 0b00000001:
			localFlag = self.__flag >> 2 & 0b111
			if localFlag >= 3:
				self.__flag = self.__flag & 0b00100011 | 0b00001100
			elif localFlag >= 1:
				self.__flag = self.__flag & 0b00100011 | 0b00000100
			else:
				print("Please load the database before checking. ")
				return False
		else:
			print("Please initialize the updater and load the database before checking the database. ")
			return False
		validity, d = self.__databaseManager.check()
		if validity:
			if d:
				print("Failed to pass the database check according to the equation system. ")
				for key, value in d.items():
					print("\t{0} -> {1}".format(key, value))
			else:
				self.__flag += 0b00000100
				print("Successfully passed the database check according to the equation system. ")
				return True
		else:
			print("Failed to check the database according to the equation system due to {0}. ".format(repr(d)))
		return False
	def synchronizeDatabase(self:object, targetURLs:OrderedDict|dict) -> bool: # 0b00?01011 + 0b00000100 -> 0b00?01111
		if self.__flag & 0b00000010 and self.__flag & 0b00000001 and self.__flag >> 2 & 0b111 >= 2 and isinstance(targetURLs, (OrderedDict, dict)):
			self.__flag, localFlag = self.__flag & 0b00100011 | 0b00001000, bool(targetURLs)
			for key, value in targetURLs.items():
				if key in ('D', 'M'):
					validity, delta, d = self.__databaseManager.updateFromURLs(value, key)
					if validity:
						if d:
							localFlag = False
							print("Updated {0} package name(s) of ${1}$ from {2} with the following base exception(s). ".format(delta, key, value))
							for key, value in d.items():
								print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
						else:
							print("Successfully updated {0} package name(s) of ${1}$ from {2}. ".format(delta, key, value))
					else:
						localFlag = False
						print("Failed to update package names of ${0}$ from {1} due to {2}. ".format(key, value, repr(d)))
				else:
					print("The key passed was neither \'D\' nor \'M\'. ")
			if localFlag:
				self.__flag += 0b00000100
				return True
		else:
			print("Please check the database and the parameter types before synchronizing. ")
		return False
	def saveDatabase(self:object) -> bool: # 0b00?10011 + 0b00000100 -> 0b00?10111
		if self.__flag & 0b00000010 and self.__flag & 0b00000001 and self.__flag >> 2 & 0b111 >= 4:
			self.__flag = self.__flag & 0b00100011 | 0b00010000
			validity, exception = self.__databaseManager.save()
			if validity:
				self.__flag += 0b00000100
				print("Successfully wrote the database to the database file {0}. ".format(repr(self.__databaseFilePath)))
				return True
			else:
				print("Failed to write the database to the database file {0} due to {1}. ".format(repr(self.__databaseFilePath), repr(exception)))
		else:
			print("Please check the database again before saving. ")
		return False
	def compileCPP(self:object, cppSourceFolderPath:str, cppSourceMainFileName:str, forceCompilation:bool = False) -> bool: # 0b00?10111 + 0b00000100 -> 0b00?11011
		if self.__flag & 0b00000010 and self.__flag & 0b00000001 and self.__flag >> 2 & 0b111 >= 5:
			self.__flag = self.__flag & 0b00100011 | 0b00010100
			localFlag = True
			tripleABI = (
				["aarch64-linux-android21", "arm64-v8a", None], ["armv7a-linux-androideabi21", "armeabi-v7a", None], 
				["x86_64-linux-android21", "x86_64", None], ["i686-linux-android21", "x86", None]
			)
			for entryABI in tripleABI:
				keyABI, valueABI, _ = entryABI
				try:
					cppBinaryFilePath = os.path.join(self.__webrootFolderPath, "{0}_{1}".format(cppSourceMainFileName, valueABI))
					entryABI[2] = cppBinaryFilePath
					if not os.path.isfile(cppBinaryFilePath):
						localFlag = False
				except:
					localFlag = False
			if localFlag:
				try:
					if isinstance(forceCompilation, bool) and forceCompilation:
						choice = True
					else:
						choice = input("CPP executable binaries existing, would you like to compile the CPP sources again [yN]? ").upper() in RegularUpdater.__PositiveAnswers
				except:
					choice = False
			else:
				choice = True
			if choice:
				localFlag = True
				cppSourceFilePath = os.path.join(cppSourceFolderPath, cppSourceMainFileName + ".cpp")
				for keyABI, valueABI, cppBinaryFilePath in tripleABI:
					try:
						result = run((
							"{0}-clang++".format(keyABI), "-O3", "-Wall", "-Wextra", "-Wpedantic", "-I", cppSourceFolderPath, 
							cppSourceFilePath, "-o", cppBinaryFilePath, "-static-libstdc++", "-fPIE", "-pie"
						), capture_output = True, text = True, timeout = RegularUpdater.__DefaultTimeout)
						if result.returncode != EXIT_SUCCESS:
							localFlag = False
							print("Failed to compile {0} to {1} due to errors {2}. ".format(repr(cppSourceFilePath), repr(cppBinaryFilePath), repr(result)))
						elif result.stdout or result.stderr:
							localFlag = False
							print("Compiled {0} to {1} with warnings {2}. ".format(repr(cppSourceFilePath), repr(cppBinaryFilePath), repr(result)))
						else:
							print("Successfully compiled {0} to {1} without errors or warnings. ".format(repr(cppSourceFilePath), repr(cppBinaryFilePath)))
					except TimeoutExpired as e:
						localFlag = False
						print("Failed to compile the CPP due to {0}. ".format({"cmd":e.cmd, "stderr":e.stderr, "stdout":e.stdout, "timeout":e.timeout}))
					except BaseException as e:
						localFlag = False
						print("Failed to compile the CPP due to {0}. ".format(repr(e)))
				if localFlag:
					self.__flag += 0b00000100
					return True
			else:
				self.__flag += 0b00000100
				return True
		else:
			print("Please save the database before compiling the CPP. ")
		return False
	def compress(self:object, extensionsExcluded:tuple|list|set) -> bool: # 0b00?11011 | 0b00011100 -> 0b00?11111
		if self.__flag & 0b00000010 and self.__flag & 0b00000001 and self.__flag >> 2 & 0b111 >= 6 and isinstance(extensionsExcluded, (tuple, list, set)):
			self.__flag = self.__flag & 0b00100011 | 0b00011000
			if os.path.isdir(self.__webrootFolderPath):
				try:
					with ZipFile(self.__webrootFilePath, "w") as zipf:
						for root, _, fileNames in os.walk(self.__webrootFolderPath):
							for fileName in fileNames:
								if os.path.splitext(fileName)[1] not in extensionsExcluded:
									filePath = os.path.join(root, fileName)
									relativePath = os.path.relpath(filePath, self.__webrootFolderPath)
									zipInfo = ZipInfo(relativePath)
									zipInfo.external_attr = 0o644 << 16
									with open(filePath, "rb") as f:
										zipf.writestr(zipInfo, f.read())
					self.__flag |= 0b00011100
					print("Successfully compressed the web UI folder {0} to {1}. ".format(repr(self.__webrootFolderPath), repr(self.__webrootFilePath)))
					return True
				except BaseException as e:
					print("Failed to compress the web UI folder {0} to {1} due to {2}. ".format(repr(self.__webrootFolderPath), repr(self.__webrootFilePath), repr(e)))
			else:
				print("The webroot folder path {0} does not exist or exists not as a folder. ".format(repr(self.__webrootFolderPath))) 
		else:
			print("Please compile the CPP before compressing the webroot folder. ")
		return False
	def checkShell(self:object) -> bool: # 0b000???11 | 0b00100000 -> 0b001???11
		if self.__flag & 0b00000010 and self.__flag & 0b00000001:
			self.__flag &= 0b00011111
			filePaths = []
			try:
				for root, _, fileNames in os.walk(self.__srcFolderPath):
					for fileName in fileNames:
						if os.path.splitext(fileName)[1] == ".sh":
							filePaths.append(os.path.join(root, fileName))
			except BaseException as e:
				print("Failed to walk {0} due to {1}. ".format(repr(self.__srcFolderPath), repr(e)))
			filePaths.sort()
			totalCount = len(filePaths)
			if totalCount:
				length, successCount = len(str(totalCount)), 0
				for i, filePath in enumerate(filePaths, start = 1):
					try:
						result = run(("bash", "-n", filePath), capture_output = True, text = True, timeout = RegularUpdater.__DefaultTimeout)
						if EXIT_SUCCESS == result.returncode:
							successCount += 1
							print("[{{0:0>{0}}}] {{1}} -> Passed (bash)".format(length).format(i, repr(filePath)))
						else:
							print("[{{0:0>{0}}}] {{1}} -> Failed (bash) -> {{2}}".format(length).format(i, repr(filePath), result))
					except TimeoutExpired as e:
						print("[{{0:0>{0}}}] {{1}} -> Failed (bash) -> {{2}}".format(length).format(i, repr(filePath), {
							"cmd":e.cmd, "stderr":e.stderr, "stdout":e.stdout, "timeout":e.timeout
						}))
					except BaseException as e:
						print("[{{0:0>{0}}}] {{1}} -> Failed (bash) -> {{2}}".format(length).format(i, repr(filePath), repr(e)))
				try:
					with open(self.__actionAFilePath, "rb") as f:
						contentA = f.read()
					with open(self.__actionBFilePath, "rb") as f:
						contentB = f.read()
					if contentA.replace(b"readonly currentAB=\"A\"", b"readonly currentAB=\"B\"").replace(b"readonly targetAB=\"B\"", b"readonly targetAB=\"A\"") == contentB:
						print("Successfully verified the differences between {0} and {1}. ".format(repr(self.__actionAFilePath), repr(self.__actionBFilePath)))
						if successCount == totalCount:
							self.__flag |= 0b00100000
							return True					
					else:
						localFlag = False
						print("Failed to verify the differences between {0} and {1}. ".format(repr(self.__actionAFilePath), repr(self.__actionBFilePath)))
				except BaseException as e:
					localFlag = False
					print("Failed to verify the differences between {0} and {1} due to {2}".format(repr(self.__actionAFilePath), repr(self.__actionBFilePath), repr(e)))
			else:
				print("The source folder path {0} does not contain any shell scripts. ".format(repr(self.__srcFolderPath)))
		else:
			print("Please initialize the updater before checking differences. ")
		return False
	def updateSHA512(self:object, encoding:str = "utf-8") -> bool: # 0b00111111 + 0b01000000 -> 0b01111111
		if self.__flag & 0b00100000 and self.__flag & 0b00010000 and self.__flag & 0b00001000 and self.__flag & 0b00000100 and self.__flag & 0b00000010 and self.__flag & 0b00000001:
			self.__flag &= 0b00111111
			filePaths = []
			try:
				for root, _, fileNames in os.walk(self.__srcFolderPath):
					for fileName in fileNames:
						filePath = os.path.join(root, fileName)
						if os.path.splitext(fileName)[1] == ".sha512":
							try:
								os.remove(filePath)
							except:
								pass
						else:
							filePaths.append(filePath)
			except BaseException as e:
				print("Failed to walk {0} due to {1}. ".format(repr(self.__srcFolderPath), repr(e)), end = "")
			filePaths.sort()
			totalCount = len(filePaths)
			if totalCount:
				length, successCount = len(str(totalCount)), 0
				print("Generating SHA-512 value files for {0} item(s). ".format(totalCount))
				for i, filePath in enumerate(filePaths, start = 1):
					try:
						if os.path.join(self.__srcFolderPath, self.__webrootName + ".zip") == filePath:
							digests = []
							for root, _, fileNames in os.walk(os.path.join(self.__srcFolderPath, self.__webrootName)):
								for fileName in fileNames:
									if os.path.splitext(fileName)[1].lower() not in (".prop", ".sha512"):
										fileP = os.path.join(root, fileName)
										with open(fileP, "rb") as f:
											digests.append(sha512(f.read()).hexdigest() + "  " + os.path.relpath(fileP, self.__srcFolderPath))
							digests.sort()
							digest = "\n".join(digests)
						else:
							with open(filePath, "rb") as f:
								digest = sha512(f.read()).hexdigest()
					except BaseException as e:
						print("[{{0:0>{0}}}] \"{{1}}\" -> {{2}}".format(length).format(i, filePath, e))
						continue
					try:
						with open(filePath + ".sha512", "w", encoding = encoding) as f:
							f.write(digest)
						successCount += 1
						print("[{{0:0>{0}}}] \"{{1}}\" -> {{2}}".format(length).format(i, filePath, digest if digest.isalnum() else digest.split("\n")))
					except BaseException as e:
						print("[{{0:0>{0}}}] \"{{1}}\" -> {{2}}".format(length).format(i, filePath, e))
				print("Successfully generated {0} / {1} SHA-512 value file(s) at the success rate of {2:.2f}%. ".format(successCount, totalCount, successCount * 100 / totalCount))
				if successCount == totalCount:
					self.__flag += 0b01000000
					return True
			else:
				print("No SHA-512 value files were generated. ")
		else:
			print("Please compress the webroot folder and check the shell scripts before updating SHA-512. ")
		return False
	def gitPush(self:object, pushConfirmed:bool = False) -> bool: # 0b10111111 | 0b11000000 -> 0b11111111
		if (
			self.__flag & 0b00100000 and self.__flag & 0b00010000 and self.__flag & 0b00001000 and self.__flag & 0b00000100
			and self.__flag & 0b00000010 and self.__flag & 0b00000001 and self.__flag >> 6 >= 2
		):
			self.__flag = self.__flag & 0b00111111 | 0b10000000
			if "posix" == os.name:
				try:
					if isinstance(pushConfirmed, bool) and pushConfirmed:
						choice = True
					else:
						choice = input("Would you like to upload the files to GitHub via ``git`` [yN]? ").upper() in RegularUpdater.__PositiveAnswers
				except:
					choice = False
			else:
				choice = False
				print("Skipped pushing since this is not a Linux platform. ")
			if choice:
				commitMessage = "Regular Update (HKT {0})".format(datetime.now().strftime("%Y%m%d%H%M%S%f"))
				print("The commit message is \"{0}\". ".format(commitMessage))
				commandlines = ("git add .", "git commit -m \"{0}\"".format(commitMessage), "git push")
				for commandline in commandlines:
					if os.system(commandline) != EXIT_SUCCESS:
						return False
				self.__flag |= 0b11000000
				return True
			else:
				return True
		else:
			print("Please set permissions again before pushing. ")
			return False


def main() -> int:
	# Parameters #
	srcFolderPath = "src"
	webrootName = "webroot"
	databaseFileName = "database.json"
	actionAFileName, actionBFileName = "actionA.sh", "actionB.sh"
	selfURL = "https://raw.githubusercontent.com/LRFP-Team/LRFP/main/Detectors/README.json"
	pluginURL = "https://modules.lsposed.org/modules.json"
	cppSourceFolderPath = "cpp"
	cppSourceMainFileName = "generate"
	extensionsExcluded = (".prop", ".sha512")
	
	# Updater #
	regularUpdater = RegularUpdater(srcFolderPath, webrootName, databaseFileName, actionAFileName, actionBFileName)
	if regularUpdater.gitPull() and regularUpdater.setPermissions() and regularUpdater.loadDatabase() and regularUpdater.checkDatabase():
		databaseFlag = (
			regularUpdater.synchronizeDatabase({"D":selfURL, "M":pluginURL}) and regularUpdater.checkDatabase() and regularUpdater.saveDatabase()
			and regularUpdater.compileCPP(cppSourceFolderPath, cppSourceMainFileName) and regularUpdater.compress(extensionsExcluded)
		)
		differenceFlag = regularUpdater.checkShell()
		if databaseFlag and differenceFlag:
			errorLevel = EXIT_SUCCESS if regularUpdater.updateSHA512() and regularUpdater.setPermissions() and regularUpdater.gitPush() else EXIT_FAILURE
		else:
			errorLevel = EXIT_FAILURE
	else:
		errorLevel = EOF
	
	# Exit #
	print("Please press the enter key to exit ({0}). ".format(errorLevel))
	try:
		getpass("")
	except:
		print()
	return errorLevel



if "__main__" == __name__:
	exit(main())