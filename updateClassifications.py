import os
from sys import exit
from datetime import datetime
from hashlib import sha512
from json import loads
from re import findall
from subprocess import PIPE, Popen
from zipfile import ZipFile
try:
	from requests import get
except:
	def get(url:str, *args:tuple, **kwargs:dict) -> None:
		return None
	print("Cannot import ``get`` from the ``requests`` library. Fetching from URLs will be unavailable. ")
	print("Please try to install the ``requests`` library correctly via ``python -m pip install requests`` or ``apt-get install python3-requests``. ")
try:
	os.chdir(os.path.abspath(os.path.dirname(__file__)))
except:
	pass
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EOF = (-1)


class SortedUniqueList(list):
	def __init__(self:object, s:object = None, exclusion:object = {"com.google.android.gsf", "com.google.android.gms", "com.android.vending"}) -> object:
		super().__init__()
		self.__exclusion = set(exclusion) if isinstance(exclusion, (tuple, list, set, str, SortedUniqueList)) else set()
		if isinstance(s, (tuple, list, set, str, SortedUniqueList)):
			for value in s:
				if value not in self and value not in self.__exclusion:
					super().append(value)
			self.sort()
	def add(self, value:object) -> None:
		return self.append(value)
	def append(self, value:object) -> None:
		if value not in self and value not in self.__exclusion:
			super().append(value)
		self.sort()
	def extend(self, s:object) -> None:
		if isinstance(s, (tuple, list, set, str, SortedUniqueList)):
			for value in s:
				if value not in self and value not in self.__exclusion:
					super().append(value)
		self.sort()
	def update(self:object, s:object) -> object:
		if isinstance(s, (tuple, list, set, str, SortedUniqueList)):
			return self.extend(s)
	def intersection(self:object, other:object) -> object:
		if isinstance(other, (tuple, list, set, str, SortedUniqueList)):
			return set(self).intersection(other)

class Classification:
	urlCache = {}
	timeout = 10
	def __init__(self:object, name:str = 'S', s:object = None, exclusion:object = {"com.google.android.gsf", "com.google.android.gms", "com.android.vending"}) -> object:
		if isinstance(s, (tuple, list, set, str, SortedUniqueList)):
			self.__s = SortedUniqueList(s, exclusion = exclusion if isinstance(exclusion, (tuple, list, set, str, SortedUniqueList)) else None)
		else:
			self.__s = SortedUniqueList(exclusion = exclusion if isinstance(exclusion, (tuple, list, set, str, SortedUniqueList)) else None)
		self.__name = name if isinstance(name, str) and len(name) == 1 and ('A' <= name <= 'Z' or 'a' <= name <= 'z') else 'S'
		self.__pattern = "^[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+$"
	def __getTxt(self:object, filePath:str) -> str|None: # get ``*.txt`` content
		for coding in ("utf-8", "ANSI", "utf-16", "gbk"): # codings (add more codings here if necessary)
			try:
				with open(filePath, "r", encoding = coding) as f:
					content = f.read()
				return content[1:] if content.startswith("\ufeff") else content # if utf-8 with BOM, remove BOM
			except (UnicodeError, UnicodeDecodeError):
				continue
			except:
				return None
		return None
	def __getUrl(self:object, url:str, forceUpdate:bool = False) -> tuple: # get URL content
		if isinstance(url, str) and isinstance(forceUpdate, bool):
			if forceUpdate or url not in Classification.urlCache:
				try:
					r = get(url, timeout = Classification.timeout)
					if r is None:
						return (False, "The ``get`` is currently unavailable. ")
					elif 200 == r.status_code:
						Classification.urlCache[url] = r.text
						return (True, r.text)
					else:
						return (False, r)
				except BaseException as e:
					return (False, str(e))
			else:
				return (True, Classification.urlCache[url])
		else:
			return (False, "At least one of the parameters passed is invalid. ")
	def configureSet(self:object, s:set|tuple|list, updateSwitch:bool = True) -> bool:
		if isinstance(s, (set, tuple, list)) and isinstance(updateSwitch, bool):
			if not updateSwitch:
				self.__s.clear()
			originalSize = len(self.__s)
			self.__s.update(s)
			currentSize = len(self.__s)
			sizeDelta = currentSize - originalSize
			print("Successfully updated {0} package name(s). ".format(sizeDelta))
			return True
		else:
			print("The parameters passed are in wrong types. ")
			return False
	def configureFile(self:object, filePath:str, updateSwitch:bool = True) -> bool:
		if isinstance(filePath, str) and isinstance(updateSwitch, bool):
			content = self.__getTxt(filePath)
			if isinstance(content, str):
				if not updateSwitch:
					self.__s.clear()
				originalSize = len(self.__s)
				for line in content.splitlines():
					self.__s.update(findall(self.__pattern, line))
				currentSize = len(self.__s)
				sizeDelta = currentSize - originalSize
				print("Successfully updated {0} package name(s) for Classification ${1}$ from the file \"{2}\". ".format(sizeDelta, self.__name, filePath))
				return True
			else:
				print("Failed to update for Classification ${0}$ from the file \"{1}\" due to file reading failures. ".format(self.__name, filePath))
		else:
			print("The parameters passed are in wrong types. ")
			return False
	def configureUrl(self:object, url:str, isDesktop:bool = False, updateSwitch:bool = True) -> bool:
		if isinstance(url, str) and isinstance(isDesktop, bool) and isinstance(updateSwitch, bool):
			status, content = self.__getUrl(url)
			if status:
				if not updateSwitch:
					self.__s.clear()
				originalSize = len(self.__s)
				vector = loads(content)
				if isinstance(vector, list):
					for v in vector:
						if isinstance(v, dict) and "name" in v:
							self.__s.update(findall(self.__pattern, v["name"]))
				elif isinstance(vector, dict) and "Detectors" in vector and isinstance(vector["Detectors"], list):
					if isDesktop:
						for v in vector["Detectors"]:
							if isinstance(v, dict) and "packageName" in v and "sourceStatus" in v and "D" in v["sourceStatus"] and "developingPurpose" in v and "D" in v["developingPurpose"]:
								if isinstance(v["packageName"], (tuple, list, set)):
									for pkg in v["packageName"]:
										self.__s.update(findall(self.__pattern, pkg))
								else:
									self.__s.update(findall(self.__pattern, v["packageName"]))
					else:
						for v in vector["Detectors"]:
							if isinstance(v, dict) and "packageName" in v and "sourceStatus" in v and "D" not in v["sourceStatus"] and "developingPurpose" in v and "D" not in v["developingPurpose"]:
								if isinstance(v["packageName"], (tuple, list, set)):
									for pkg in v["packageName"]:
										self.__s.update(findall(self.__pattern, pkg))
								else:
									self.__s.update(findall(self.__pattern, v["packageName"]))
				else:
					print("Failed to update from the URL \"{0}\" due to the unrecognized data structure. ".format(url))
					return False
				currentSize = len(self.__s)
				sizeDelta = currentSize - originalSize
				print("Successfully updated {0} package name(s) for Classification ${1}$ from the URL \"{2}\". ".format(sizeDelta, self.__name, url))
				return True
			else:
				print("Failed to update for Classification ${0}$ from the URL \"{1}\". Details are as follows. \n\t{2}".format(self.__name, url, content))
				return False
		else:
			print("The parameters passed are in wrong types. ")
			return False
	def intersection(self:object, other:object) -> set:
		return other.intersection(self.__s)
	def writeTo(self:object, filePath:str, encoding:str = "utf-8") -> bool:
		try:
			with open(filePath, "w", encoding = encoding) as f:
				f.write(str(self))
			print("Successfully wrote {0} lines to the file \"{1}\" for Classification ${2}$. ".format(len(self), filePath, self.__name))
			return True
		except BaseException as e:
			print("Failed to write to the file \"{0}\" for Classification ${1}$ due to exceptions. Details are as follows. \n\t{2}".format(filePath, self.__name, e))
			return False
	def __len__(self:object) -> int:
		return len(self.__s)
	def __str__(self:object) -> str:
		return "\n".join(sorted(self.__s))


def updateSHA512(srcFp:str, encoding:str = "utf-8") -> bool:
	if isinstance(srcFp, str) and os.path.isdir(srcFp) and isinstance(encoding, str):
		successCnt, filePaths = 0, []
		for root, dirs, files in os.walk(srcFp):
			for fileName in files:
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
				if filePath == os.path.join(srcFp, "webroot.zip"):
					digests = []
					for root, dirs, files in os.walk(os.path.join(srcFp, "webroot")):
						for fileName in files:
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
		print("Successfully generated {0} / {1} SHA-512 value file(s) at the success rate of {2:.2f}%. ".format(successCnt, totalCnt, successCnt * 100 / totalCnt) if totalCnt else "No SHA-512 value files were generated. ")
		return successCnt == totalCnt
	else:
		return False

def compress(zipFolderPath:str, zipFilePath:str, extensionsExcluded:tuple|list|set) -> bool:
	if isinstance(zipFolderPath, str) and os.path.isdir(zipFolderPath) and isinstance(zipFilePath, str) and isinstance(extensionsExcluded, (tuple, list, set)):
		try:
			with ZipFile(zipFilePath, "w") as zipf:
				for root, _, files in os.walk(zipFolderPath):
					for fileName in files:
						if os.path.splitext(fileName)[1] not in extensionsExcluded:
							filePath = os.path.join(root, fileName)
							zipf.write(filePath, os.path.relpath(filePath, zipFolderPath))
			print("Successfully compressed the web UI folder \"{0}\" to \"{1}\". ".format(zipFolderPath, zipFilePath))
			return True
		except BaseException as e:
			print("Failed to compress the web UI folder \"{0}\" to \"{1}\" due to \"{2}\". ".format(zipFolderPath, zipFilePath, e))
	else:
		return False

def gitPush(filePathA:str, filePathB:str, encoding:str = "utf-8") -> bool:
	commitMessage = "Regular Update ({0})".format(datetime.now().strftime("%Y%m%d%H%M%S"))
	print("The commit message is \"{0}\". ".format(commitMessage))
	if __import__("platform").system().upper() == "WINDOWS":
		commandlines = []
		print("Cannot guarantee whether permission or syntax issues are solved due to the platform. ")
	else:
		commandlines = [																			\
			"find . -type d -exec chmod 755 {} \\;", 														\
			"find . -type f ! -name \"LICENSE\" ! -name \"build.sh\" ! -name \"*.sha512\" -exec chmod 644 {} \\;", 	\
			"find . -type f -name \"*.sha512\" -exec chmod 444 {} \\;", 										\
			"chmod 444 \"LICENSE\"", 																\
			"chmod 744 \"build.sh\"", 																\
			"find . -name \"*.sh\" -exec bash -n {} \\;"													\
		]
	for commandline in commandlines:
		with Popen(commandline, stdout = PIPE, stderr = PIPE, shell = True) as process:
			output, error = process.communicate()
			if output or error:
				print("Abort ``git`` operations due to the following issue. ")
				print({"commandline":commandline, "output":output.decode(), "error":error.decode()})
				return False
	try:
		with open(filePathA, "r", encoding = encoding) as f:
			contentA = f.read()
		with open(filePathB, "r", encoding = encoding) as f:
			contentB = f.read()
	except BaseException as e:
		print("Cannot verify the differences between \"{0}\" and \"{1}\" due to exceptions. Details are as follows. \n\t{2}".format(filePathA, filePathB, e))
		return False
	if contentA.replace("readonly currentAB=\"A\"", "readonly currentAB=\"B\"").replace("readonly targetAB=\"B\"", "readonly targetAB=\"A\"") == contentB:
		print("Successfully verified the differences between \"{0}\" and \"{1}\"".format(filePathA, filePathB))
	else:
		print("Failed to verify the differences between \"{0}\" and \"{1}\"".format(filePathA, filePathB))
		return False
	commandlines = ["git add .", "git commit -m \"{0}\"".format(commitMessage), "git push"]
	for commandline in commandlines:
		if os.system(commandline) != EXIT_SUCCESS:
			return False
	return True

def main() -> int:
	# Parameters #
	folderPath = "src/webroot/classifications"
	fileNameB, fileNameC, fileNameD = "classificationB.txt", "classificationC.txt", "classificationD.txt"
	filePathB, filePathC, filePathD = os.path.join(folderPath, fileNameB), os.path.join(folderPath, fileNameC), os.path.join(folderPath, fileNameD)
	urlB = "https://modules.lsposed.org/modules.json"
	urlCD = "https://raw.githubusercontent.com/LRFP-Team/LRFP/main/Detectors/README.json"
	srcFolderPath = "src"
	webrootName = "webroot"
	webrootFolderPath = os.path.join(srcFolderPath, webrootName)
	webrootFilePath = os.path.join(srcFolderPath, webrootName + ".zip")
	extensionsExcluded = [".prop", ".sha512"]
	actionAFileName, actionBFileName = "actionA.sh", "actionB.sh"
	actionAFilePath, actionBFilePath = os.path.join(srcFolderPath, actionAFileName), os.path.join(srcFolderPath, actionBFileName)
	bRet = True
	
	# Update $B$ #
	classificationB, classificationC, classificationD = Classification('B'), Classification('C'), Classification('D')
	bRet = classificationB.configureFile(filePathB) and bRet
	bRet = classificationB.configureUrl(urlB) and bRet
	bRet = classificationB.writeTo(filePathB) and bRet
	
	# Update $C$ #
	bRet = classificationC.configureFile(filePathC) and bRet
	bRet = classificationC.configureUrl(urlCD, isDesktop = False) and bRet
	bRet = classificationC.writeTo(filePathC) and bRet
	
	# Update $D$ #
	bRet = classificationD.configureFile(filePathD) and bRet
	bRet = classificationD.configureUrl(urlCD, isDesktop = True) and bRet
	bRet = classificationD.writeTo(filePathD) and bRet
	
	# Compute Intersections #
	setBC = classificationB.intersection(classificationC)
	setBD = classificationB.intersection(classificationD)
	setCD = classificationC.intersection(classificationD)
	if setBC:
		print("There {0} in both Classification $B$ and Classification $C$. ".format("are {0} elements".format(len(setBC)) if len(setBC) > 1 else "is {0} element".format(len(setBC))))
		print(setBC)
		bRet = False
	if setBD:
		print("There {0} in both Classification $B$ and Classification $D$. ".format("are {0} elements".format(len(setBD)) if len(setBD) > 1 else "is {0} element".format(len(setBD))))
		print(setBD)
		bRet = False
	if setCD:
		print("There {0} in both Classification $C$ and Classification $D$. ".format("are {0} elements".format(len(setCD)) if len(setCD) > 1 else "is {0} element".format(len(setCD))))
		print(setCD)
		bRet = False
	
	# Update the Web UI #
	bRet = updateSHA512(srcFolderPath) and compress(webrootFolderPath, webrootFilePath, extensionsExcluded)
	
	# Git Push #
	if bRet:
		try:
			choice = input("Would you like to upload the files to GitHub via ``git`` [Yn]? ").upper() not in ("N", "NO", "0", "FALSE")
		except:
			choice = True
		if choice:
			bRet = gitPush(actionAFilePath, actionBFilePath)
	
	# Exit #
	iRet = EXIT_SUCCESS if bRet else EXIT_FAILURE
	print("Please press the enter key to exit ({0}). ".format(iRet))
	try:
		input()
	except:
		print()
	return iRet



if "__main__" == __name__:
	exit(main())