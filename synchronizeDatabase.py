import os
from sys import exit
from codecs import lookup
from collections import OrderedDict
from datetime import datetime
from getpass import getpass
from hashlib import sha512
from json import dump, loads
from re import findall
from subprocess import PIPE, Popen
from zipfile import ZipFile
try:
	from requests import get
except:
	def get(url:str, *args:tuple, **kwargs:dict) -> None:
		return None
	print("Cannot import ``get`` from the ``requests`` library. Fetching from URLs will be unavailable. ")
	print("Please try to install the ``requests`` library correctly via ``python -m pip install requests``. ")
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
	__Caches = {}
	__Pattern = "^[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+$"
	def __init__(self:object, databaseFilePath:str = __DefaultDatabaseFilePath, timeout:int = __DefaultTimeout, encoding:str = __DefaultEncoding) -> object:
		self.__databaseFilePath = databaseFilePath if isinstance(databaseFilePath, str) else DatabaseManager.__DefaultDatabaseFilePath
		self.__timeout = timeout if isinstance(timeout, int) and timeout >= 1 else DatabaseManager.__DefaultTimeout
		try:
			lookup(encoding)
			self.__encoding = encoding
		except:
			self.__encoding = DatabaseManager.__DefaultEncoding
		self.__database = None
	def load(self:object) -> tuple:
		try:
			with open(self.__databaseFilePath, "r", encoding = self.__encoding) as f:
				self.__database = loads(f.read())
			if isinstance(self.__database, dict):
				removedKeyCount = 0
				for key in tuple(self.__database.keys()):
					if key not in ("C", "D", "M", "N", "S", "T"):
						del self.__database[key]
						removedKeyCount += 1
				if "C" in self.__database:
					for key in tuple(self.__database["C"].keys()):
						if not (isinstance(key, str) and len(key) == 1 and 'A' <= key <= 'Z'):
							del self.__database["C"][key]
							removedKeyCount += 1
				return (True, removedKeyCount)
			else:
				self.__database = None
				return (False, ValueError("The data loaded from {0} could not be recognized. ".format(repr(self.__databaseFilePath))))
		except BaseException as e:
			return (False, e)
	def __fetchPackageNamesFromURL(self:object, URL:str, d:dict) -> set:
		packageNames = set()
		if isinstance(URL, str) and isinstance(d, dict):
			if URL not in DatabaseManager.__Caches:
				r = get(URL, timeout = self.__timeout)
				if 200 == r.status_code:
					DatabaseManager.__Caches[URL] = r.content
				else:
					d[URL] = r.status_code
			if URL in DatabaseManager.__Caches:
				obj = loads(DatabaseManager.__Caches[URL])
				if isinstance(obj, list):
					for item in obj:
						if isinstance(item, dict) and "name" in item:
							packageNames.update(findall(DatabaseManager.__Pattern, item["name"]))
				elif isinstance(obj, dict) and "$D$" in obj and isinstance(obj["$D$"], list):
					for item in obj["$D$"]:
						if (
							isinstance(item, dict) and "packageName" in item and "category" in item and len(item["category"]) <= 5
							and item["category"].startswith("$D") and item["category"].endswith("$")
						):
							if isinstance(item["packageName"], (tuple, list, set)):
								for packageName in item["packageName"]:
									packageNames.update(findall(DatabaseManager.__Pattern, packageName))
							else:
								packageNames.update(findall(DatabaseManager.__Pattern, item["packageName"]))
		return packageNames
	def updateFromURLs(self:object, URLs:tuple|list|set|str, key:str, incrementalUpdate:bool = True) -> tuple:
		try:
			if isinstance(self.__database, dict) and key in ("D", "M"):
				stack, packageNames, d, originalSize = [URLs], set(), OrderedDict(), 0
				while stack:
					element = stack.pop()
					if isinstance(element, (tuple, list, set)):
						element.extend(reversed(element))
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
	def checkSatisfaction(self:object) -> tuple:
		if isinstance(self.__database, dict):
			d, C = OrderedDict(), set()
			if "C" in self.__database and isinstance(self.__database["C"], dict):
				keys = tuple(
					key for key in self.__database["C"].keys() if isinstance(key, str) and len(key) == 1
					and 'A' <= key <= 'Z' and isinstance(self.__database["C"][key], (tuple, list, set))
				)
				keyLength = len(keys)
				for i in range(keyLength - 1):
					for j in range(i + 1, keyLength):
						intersection = set(self.__database["C"][keys[i]]) & set(self.__database["C"][keys[j]])
						if intersection:
							d[("$C_{0}$".format(keys[i]), "$C_{0}$".format(keys[j]))] = intersection
				for key in keys:
					C.update(self.__database["C"][key])
			orderedDict = OrderedDict([("C", C)])
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
	def save(self:object) -> tuple:
		if isinstance(self.__database, dict):
			try:
				with open(self.__databaseFilePath, "w", encoding = self.__encoding) as f:
					dump(self.__database, f, indent = "\t", ensure_ascii = False, sort_keys = True)
				return (True, None)
			except BaseException as e:
				return (False, e)
		else:
			return (False, TypeError("The database is not a ``dict``. Please check whether the method function ``load`` has been called. "))


def compress(zipFolderPath:str, zipFilePath:str, extensionsExcluded:tuple|list|set) -> bool:
	if isinstance(zipFolderPath, str) and os.path.isdir(zipFolderPath) and isinstance(zipFilePath, str) and isinstance(extensionsExcluded, (tuple, list, set)):
		try:
			with ZipFile(zipFilePath, "w") as zipf:
				for root, _, fileNames in os.walk(zipFolderPath):
					for fileName in fileNames:
						if os.path.splitext(fileName)[1] not in extensionsExcluded:
							filePath = os.path.join(root, fileName)
							zipf.write(filePath, os.path.relpath(filePath, zipFolderPath))
			print("Successfully compressed the web UI folder \"{0}\" to \"{1}\". ".format(zipFolderPath, zipFilePath))
			return True
		except BaseException as e:
			print("Failed to compress the web UI folder \"{0}\" to \"{1}\" due to \"{2}\". ".format(zipFolderPath, zipFilePath, e))
	else:
		return False

def updateSHA512(srcFp:str, encoding:str = "utf-8") -> bool:
	if isinstance(srcFp, str) and os.path.isdir(srcFp) and isinstance(encoding, str):
		successCnt, filePaths = 0, []
		for root, _, fileNames in os.walk(srcFp):
			for fileName in fileNames:
				filePath = os.path.join(root, fileName)
				if os.path.splitext(fileName)[1] == ".sha512":
					try:
						os.remove(filePath)
					except:
						pass
				else:
					filePaths.append(filePath)
		totalCnt = len(filePaths)
		length = len(str(totalCnt))
		for i, filePath in enumerate(filePaths):
			try:
				if os.path.join(srcFp, "webroot.zip") == filePath:
					digests = []
					for root, _, fileNames in os.walk(os.path.join(srcFp, "webroot")):
						for fileName in fileNames:
							if os.path.splitext(fileName)[1].lower() not in (".prop", ".sha512"):
								fileP = os.path.join(root, fileName)
								with open(fileP, "rb") as f:
									digests.append(sha512(f.read()).hexdigest() + "  " + os.path.relpath(fileP, srcFp))
					digests.sort()
					digest = "\n".join(digests)
				else:
					with open(filePath, "rb") as f:
						digest = sha512(f.read()).hexdigest()
			except BaseException as e:
				print("[{{0:0>{0}}}] \"{{1}}\" -> {{2}}".format(length).format(i + 1, filePath, e))
				continue
			try:
				with open(filePath + ".sha512", "w", encoding = encoding) as f:
					f.write(digest)
				successCnt += 1
				print("[{{0:0>{0}}}] \"{{1}}\" -> {{2}}".format(length).format(i + 1, filePath, digest if digest.isalnum() else digest.split("\n")))
			except BaseException as e:
				print("[{{0:0>{0}}}] \"{{1}}\" -> {{2}}".format(length).format(i + 1, filePath, e))
		print("Successfully generated {0} / {1} SHA-512 value file(s) at the success rate of {2:.2f}%. ".format(	\
			successCnt, totalCnt, successCnt * 100 / totalCnt														\
		) if totalCnt else "No SHA-512 value files were generated. ")
		return successCnt == totalCnt
	else:
		return False

def gitPush(filePathA:str, filePathB:str) -> bool:
	commitMessage = "Regular Update (HKT {0})".format(datetime.now().strftime("%Y%m%d%H%M%S%f"))
	print("The commit message is \"{0}\". ".format(commitMessage))
	if __import__("platform").system().upper() == "WINDOWS":
		commandlines = ()
		print("Cannot guarantee whether permission or syntax issues are solved due to the platform. ")
	else:
		commandlines = (																							\
			"find . -type d -exec chmod 755 {} \\;", 																\
			"find . -type f ! -name \"LICENSE\" ! -name \"build.sh\" ! -name \"*.sha512\" -exec chmod 644 {} \\;", 	\
			"find . -type f -name \"*.sha512\" -exec chmod 444 {} \\;", 											\
			"chmod 444 \"LICENSE\"", 																				\
			"chmod 744 \"build.sh\"", 																				\
			"find . -name \"*.sh\" -exec bash -n {} \\;"															\
		)
	for commandline in commandlines:
		with Popen(commandline, stdout = PIPE, stderr = PIPE, shell = True) as process:
			output, error = process.communicate()
			if output or error:
				print("Abort ``git`` operations due to the following issue. ")
				print({"commandline":commandline, "output":output.decode(), "error":error.decode()})
				return False
	try:
		with open(filePathA, "rb") as f:
			contentA = f.read()
		with open(filePathB, "rb") as f:
			contentB = f.read()
	except BaseException as e:
		print("Cannot verify the differences between \"{0}\" and \"{1}\" due to exceptions. Details are as follows. \n\t{2}".format(filePathA, filePathB, e))
		return False
	if contentA.replace(b"readonly currentAB=\"A\"", b"readonly currentAB=\"B\"").replace(b"readonly targetAB=\"B\"", b"readonly targetAB=\"A\"") == contentB:
		print("Successfully verified the differences between \"{0}\" and \"{1}\"".format(filePathA, filePathB))
	else:
		print("Failed to verify the differences between \"{0}\" and \"{1}\"".format(filePathA, filePathB))
		return False
	commandlines = ("git add .", "git commit -m \"{0}\"".format(commitMessage), "git push")
	for commandline in commandlines:
		if os.system(commandline) != EXIT_SUCCESS:
			return False
	return True

def main() -> int:
	# Parameters #
	pluginURL = "https://modules.lsposed.org/modules.json"
	selfURL = "https://raw.githubusercontent.com/LRFP-Team/LRFP/main/Detectors/README.json"
	srcFolderPath = "src"
	webrootName = "webroot"
	databaseFileName = "database.json"
	extensionsExcluded = (".prop", ".sha512")
	actionAFileName, actionBFileName = "actionA.sh", "actionB.sh"
	
	# Initialization #
	webrootFolderPath = os.path.join(srcFolderPath, webrootName)
	databaseFilePath = os.path.join(webrootFolderPath, databaseFileName)
	databaseManager = DatabaseManager(databaseFilePath = databaseFilePath)
	webrootFilePath = os.path.join(srcFolderPath, webrootName + ".zip")
	actionAFilePath, actionBFilePath = os.path.join(srcFolderPath, actionAFileName), os.path.join(srcFolderPath, actionBFileName)
	
	# Load the database #
	flag = True
	validity, information = databaseManager.load()
	if validity:
		if information:
			print("Loaded {0} with {1} keys removed in total. ".format(repr(databaseFilePath), information))
		else:
			print("Successfully loaded the database from {0}. ".format(repr(databaseFilePath)))
		
		# Compute intersections #
		validity, d = databaseManager.checkSatisfaction()
		if validity:
			if d:
				flag = False
				print("Failed to pass the satisfaction check of the equation system. ")
				for key, value in d.items():
					print("\t{0} -> {1}".format(key, value))
			else:
				print("Successfully passed the satisfaction check of the equation system. ")
		else:
			flag = False
			print("Failed to check the satisfaction of the equation system due to {0}. ".format(repr(d)))
	else:
		flag = False
		print("Failed to load {0} due to {1}. ".format(repr(databaseFilePath), repr(information)))
	
	# Synchronize the database #
	if flag:
		# Update $D$ #
		validity, delta, d = databaseManager.updateFromURLs(selfURL, "D")
		if validity:
			if d:
				flag = False
				print("Updated {0} package name(s) of $D$ from the URL \"{1}\" with the following exception(s). ".format(delta, selfURL))
				for key, value in d.items():
					print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
			else:
				print("Successfully updated {0} package name(s) of $D$ from the URL \"{1}\". ".format(delta, selfURL))
		else:
			flag = False
			print("Failed to update package names of $D$ from the URL \"{0}\" due to {1}. ".format(selfURL, repr(d)))
		
		# Update $M$ #
		validity, delta, d = databaseManager.updateFromURLs(pluginURL, "M")
		if validity:
			if d:
				flag = False
				print("Updated {0} package name(s) of $M$ from the URL \"{1}\" with the following exception(s). ".format(delta, pluginURL))
				for key, value in d.items():
					print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
			else:
				print("Successfully updated {0} package name(s) of $M$ from the URL \"{1}\". ".format(delta, pluginURL))
		else:
			flag = False
			print("Failed to update package names of $M$ from the URL \"{0}\" due to {1}. ".format(pluginURL, repr(d)))
		
		# Compute intersections #
		validity, d = databaseManager.checkSatisfaction()
		if validity:
			if d:
				flag = False
				print("Failed to pass the satisfaction check of the equation system. ")
				for key, value in d.items():
					print("\t{0} -> {1}".format(key, value))
			else:
				print("Successfully passed the satisfaction check of the equation system. ")
		else:
			flag = False
			print("Failed to check the satisfaction of the equation system due to {0}. ".format(repr(d)))
		
		if flag:
			# Save #
			validity, exception = databaseManager.save()
			if validity:
				print("Successfully wrote the database to the database file {0}. ".format(repr(databaseFilePath)))
			else:
				flag = False
				print("Failed to write the database to the database file {0} due to {1}. ".format(repr(databaseFilePath), repr(exception)))
			
			if flag:
				# Update the Web UI #
				if not (compress(webrootFolderPath, webrootFilePath, extensionsExcluded) and updateSHA512(srcFolderPath)):
					flag = False
				
				if flag:
					# Git Push #
					try:
						choice = input("Would you like to upload the files to GitHub via ``git`` [Yn]? ").upper() not in ("N", "NO", "0", "F", "FALSE")
					except:
						choice = True
					if choice:
						flag = gitPush(actionAFilePath, actionBFilePath)
		errorLevel = EXIT_SUCCESS if flag else EXIT_FAILURE
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