import os
from sys import exit
from collections import OrderedDict
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
	print("Please try to install the ``requests`` library correctly via ``python -m pip install requests``. ")
try:
	os.chdir(os.path.abspath(os.path.dirname(__file__)))
except:
	pass
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EOF = (-1)


class SortedUniqueList(list):
	def __init__(self:object, elements:tuple|list|set|str|bytes|object = None) -> object:
		super().__init__()
		self += elements
	def add(self:object, elements:tuple|list|set|str|bytes|object = None) -> None:
		self += elements
	def append(self:object, elements:tuple|list|set|str|bytes|object = None) -> None:
		self += elements
	def extend(self:object, elements:tuple|list|set|str|bytes|object = None) -> None:
		self += elements
	def update(self:object, elements:tuple|list|set|str|bytes|object = None) -> None:
		self += elements
	def intersection(self:object, other:tuple|list|set|str|bytes|object) -> object:
		return self & other
	def remove(self:object, elements:tuple|list|set|str|bytes|object) -> None:
		self -= elements
		return self
	def __and__(self:object, other:tuple|list|set|str|bytes|object) -> object:
		return SortedUniqueList(set(self) & set(other)) if isinstance(other, SortedUniqueList) else self.intersection(SortedUniqueList(other))
	def __iadd__(self:object, elements:tuple|list|set|str|bytes|object = None) -> object:
		if isinstance(elements, (tuple, list, set, SortedUniqueList, SortedUniquePackageNames)):
			for element in elements:
				self += element
		elif isinstance(elements, (str, bytes)):
			if elements not in self:
				super().append(elements)
			self.sort()
		return self
	def __isub__(self:object, elements:tuple|list|set|str|bytes|object) -> object:
		if isinstance(elements, (tuple, list, set, SortedUniqueList, SortedUniquePackageNames)):
			for element in elements:
				self -= element
		elif isinstance(elements, (str, bytes)) and elements in self:
			super().remove(elements)
		return self

class SortedUniquePackageNames(SortedUniqueList):
	Pattern = b"^[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+$"
	def __and__(self:object, other:tuple|list|set|bytes|SortedUniqueList|object) -> object:
		return SortedUniquePackageNames(set(self) & set(other)) if isinstance(other, SortedUniquePackageNames) else self.intersection(SortedUniquePackageNames(other))
	def __iadd__(self:object, packageNames:tuple|list|set|bytes|SortedUniqueList|object = None) -> object:
		if isinstance(packageNames, (tuple, list, set, SortedUniqueList, SortedUniquePackageNames)):
			for packageName in packageNames:
				self += packageName
		elif isinstance(packageNames, bytes) and findall(SortedUniquePackageNames.Pattern, packageNames):
			if packageNames not in self:
				super().__iadd__(packageNames)
		return self
	def __isub__(self:object, packageNames:tuple|list|set|bytes|SortedUniqueList|object = None) -> object:
		if isinstance(packageNames, (tuple, list, set, SortedUniqueList, SortedUniquePackageNames)):
			for packageName in packageNames:
				self -= packageName
		elif isinstance(packageNames, bytes) and packageNames in self:
			super().__isub__(packageNames)
		return self

class Classification:
	Caches = {}
	def __init__(self:object, packageNames:tuple|list|set|bytes|SortedUniqueList|SortedUniquePackageNames = None, timeout:int = 10) -> object:
		self.__packageNames = packageNames if isinstance(packageNames, SortedUniquePackageNames) else SortedUniquePackageNames(packageNames)
		self.__timeout = timeout if isinstance(timeout, int) and timeout >= 1 else 10
	def update(self:object, packageNames:tuple|list|set|bytes|SortedUniqueList|SortedUniquePackageNames|object = None, cleanUpdate:bool = False) -> int:
		if isinstance(cleanUpdate, bool) and cleanUpdate:
			self.__packageNames.clear()
		originalSize = len(self.__packageNames)
		self.__packageNames += packageNames.__packageNames if isinstance(packageNames, Classification) else packageNames
		return len(self.__packageNames) - originalSize
	def updateFromFiles(self:object, filePaths:tuple|list|set|str|SortedUniqueList, cleanUpdate:bool = False) -> tuple:
		if isinstance(cleanUpdate, bool) and cleanUpdate:
			self.__packageNames.clear()
		originalSize, d = len(self.__packageNames), OrderedDict()
		if isinstance(filePaths, (tuple, list, set)):
			for filePath in SortedUniqueList(filePaths):
				if isinstance(filePath, str):
					d.update(self.updateFromFiles(filePath, cleanUpdate = False)[1])
		elif isinstance(filePaths, SortedUniqueList):
			for filePath in filePaths:
				if isinstance(filePath, str):
					d.update(self.updateFromFiles(filePath, cleanUpdate = False)[1])
		elif isinstance(filePaths, str):
			try:
				with open(filePaths, "rb") as f:
					self.__packageNames += f.read().splitlines()
			except BaseException as e:
				d[filePaths] = e
		return (len(self.__packageNames) - originalSize, d)
	def updateFromURLs(self:object, URLs:tuple|list|set|str|SortedUniqueList, isDesktop:bool = False, cleanUpdate:bool = False) -> bool:
		if isinstance(cleanUpdate, bool) and cleanUpdate:
			self.__packageNames.clear()
		originalSize, d = len(self.__packageNames), OrderedDict()
		if isinstance(URLs, (tuple, list, set)):
			for URL in SortedUniqueList(URLs):
				if isinstance(URL, str):
					d.update(self.updateFromURLs(URL, cleanUpdate = False)[1])
		elif isinstance(URLs, SortedUniqueList):
			for URL in URLs:
				if isinstance(URL, str):
					d.update(self.updateFromURLs(URL, cleanUpdate = False)[1])
		elif isinstance(URLs, str):
			if URLs not in Classification.Caches:
				try:
					r = get(URLs, timeout = self.__timeout)
					if 200 == r.status_code:
						Classification.Caches[URLs] = r.content
					else:
						d[URLs] = r.status_code
				except BaseException as e:
					d[URLs] = e
			if URLs in Classification.Caches:
				vector = loads(Classification.Caches[URLs])
				if isinstance(vector, list):
					for v in vector:
						if isinstance(v, dict) and "name" in v:
							self.__packageNames += findall(SortedUniquePackageNames.Pattern, bytes(v["name"], encoding = "utf-8"))
				elif isinstance(vector, dict) and "Detectors" in vector and isinstance(vector["Detectors"], list):
					if isDesktop:
						for v in vector["Detectors"]:
							if (																									\
								isinstance(v, dict) and "packageName" in v and "sourceStatus" in v and "D" in v["sourceStatus"]		\
								and "developingPurpose" in v and "D" in v["developingPurpose"]										\
							):
								if isinstance(v["packageName"], (tuple, list, set)):
									for packageName in v["packageName"]:
										self.__packageNames += findall(SortedUniquePackageNames.Pattern, bytes(packageName, encoding = "utf-8"))
								else:
									self.__packageNames += findall(SortedUniquePackageNames.Pattern, bytes(v["packageName"], encoding = "utf-8"))
					else:
						for v in vector["Detectors"]:
							if (																										\
								isinstance(v, dict) and "packageName" in v and "sourceStatus" in v and "D" not in v["sourceStatus"]		\
								and "developingPurpose" in v and "D" not in v["developingPurpose"]										\
							):
								if isinstance(v["packageName"], (tuple, list, set)):
									for packageName in v["packageName"]:
										self.__packageNames += findall(SortedUniquePackageNames.Pattern, bytes(packageName, encoding = "utf-8"))
								else:
									self.__packageNames += findall(SortedUniquePackageNames.Pattern, bytes(v["packageName"], encoding = "utf-8"))
				else:
					d[URLs] = "The data structure could not be recognized. "
		return (len(self.__packageNames) - originalSize, d)
	def intersection(self:object, other:tuple|list|set|bytes|SortedUniqueList|SortedUniquePackageNames|object) -> object:
		return self & other
	def remove(self:object, packageNames:tuple|list|set|bytes|SortedUniqueList|SortedUniquePackageNames|object = None) -> int:
		originalSize = len(self.__packageNames)
		self.__packageNames.remove(packageNames)
		return len(self.__packageNames) - originalSize
	def removeFromFiles(self:object, filePaths:tuple|list|set|str|SortedUniqueList, cleanUpdate:bool = False) -> tuple:
		if isinstance(cleanUpdate, bool) and cleanUpdate:
			self.__packageNames.clear()
		originalSize, d = len(self.__packageNames), OrderedDict()
		if isinstance(filePaths, (tuple, list, set)):
			for filePath in SortedUniqueList(filePaths):
				if isinstance(filePath, str):
					d.update(self.removeFromFiles(filePath, cleanUpdate = False)[1])
		elif isinstance(filePaths, SortedUniqueList):
			for filePath in filePaths:
				if isinstance(filePath, str):
					d.update(self.removeFromFiles(filePath, cleanUpdate = False)[1])
		elif isinstance(filePaths, str):
			try:
				with open(filePaths, "rb") as f:
					self.__packageNames -= f.read().splitlines()
			except BaseException as e:
				d[filePaths] = e
		return (len(self.__packageNames) - originalSize, d)
	def saveTo(self:object, filePath:str) -> int|BaseException:
		try:
			with open(filePath, "wb") as f:
				f.write(bytes(self))
			return len(self)
		except BaseException as e:
			return e
	def getBytes(self:object, prefix:bytes = b"", suffix:bytes = b"") -> bytes:
		prefixBytes, suffixBytes = prefix if isinstance(prefix, bytes) else b"", suffix if isinstance(suffix, bytes) else b""
		return b"\n".join(prefixBytes + packageName + suffixBytes for packageName in self.__packageNames)
	def __and__(self:object, other:tuple|list|set|bytes|SortedUniqueList|SortedUniquePackageNames|object) -> object:
		return Classification(self.__packageNames & (other.__packageNames if isinstance(other, Classification) else other))
	def __bytes__(self:object) -> bytes:
		return b"\n".join(self.__packageNames)
	def __len__(self:object) -> int:
		return len(self.__packageNames)


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
	classificationFolderName = "classifications"
	labelLRFPFileName, labelDetectorFileName, labelApplicationFileName, labelSystemFileName = "classificationB.txt", "classificationC.txt", "classificationD.txt", "classificationS.txt"
	trickyStoreTargetExclusionFileName = "trickyStoreTargetExclusions.txt"
	extensionsExcluded = (".prop", ".sha512")
	actionAFileName, actionBFileName = "actionA.sh", "actionB.sh"
	
	# Initialization #
	webrootFolderPath = os.path.join(srcFolderPath, webrootName)
	classificationFolderPath = os.path.join(webrootFolderPath, classificationFolderName)
	labelLRFPFilePath, labelDetectorFilePath, labelApplicationFilePath, labelSystemFilePath, trickyStoreTargetExclusionFilePath = (					\
		os.path.join(classificationFolderPath, labelLRFPFileName), os.path.join(classificationFolderPath, labelDetectorFileName), 					\
		os.path.join(classificationFolderPath, labelApplicationFileName), os.path.join(classificationFolderPath, labelSystemFileName), 																			\
		os.path.join(classificationFolderPath, trickyStoreTargetExclusionFileName)		\
	)
	webrootFilePath = os.path.join(srcFolderPath, webrootName + ".zip")
	actionAFilePath, actionBFilePath = os.path.join(srcFolderPath, actionAFileName), os.path.join(srcFolderPath, actionBFileName)
	flag, labelLRFP, labelDetector, labelApplication, labelSystem, trickyStoreTargetExclusions = True, Classification(), Classification(), Classification(), Classification(), Classification()
	
	# Update the LRFP label #
	delta, d = labelLRFP.updateFromFiles(labelLRFPFilePath)
	if d:
		flag = False
		print("Updated {0} package name(s) of the LRFP label from the file \"{1}\" with the following exception(s). ".format(delta, labelLRFPFilePath))
		for key, value in d.items():
			print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
	else:
		print("Successfully updated {0} package name(s) of the LRFP label from the file \"{1}\". ".format(delta, labelLRFPFilePath))
	delta, d = labelLRFP.updateFromURLs(pluginURL)
	if d:
		flag = False
		print("Updated {0} package name(s) of the LRFP label from the URL \"{1}\" with the following exception(s). ".format(delta, pluginURL))
		for key, value in d.items():
			print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
	else:
		print("Successfully updated {0} package name(s) of the LRFP label from the URL \"{1}\". ".format(delta, pluginURL))
	countLRFP = labelLRFP.saveTo(labelLRFPFilePath)
	if isinstance(countLRFP, int):
		print("Successfully wrote {0} package name(s) of the LRFP label to the file \"{1}\". ".format(countLRFP, labelLRFPFilePath))
	else:
		print("Failed to write the package name(s) of the LRFP label to the file \"{0}\" due to {1}. ".format(labelLRFPFilePath, repr(countLRFP)))
	
	# Update the detector label #
	delta, d = labelDetector.updateFromFiles(labelDetectorFilePath)
	if d:
		flag = False
		print("Updated {0} package name(s) of the detector label from the file \"{1}\" with the following exception(s). ".format(delta, labelDetectorFilePath))
		for key, value in d.items():
			print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
	else:
		print("Successfully updated {0} package name(s) of the detector label from the file \"{1}\". ".format(delta, labelDetectorFilePath))
	delta, d = labelDetector.updateFromURLs(selfURL, isDesktop = False)
	if d:
		flag = False
		print("Updated {0} package name(s) of the detector label from the URL \"{1}\" with the following exception(s). ".format(delta, selfURL))
		for key, value in d.items():
			print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
	else:
		print("Successfully updated {0} package name(s) of the detector label from the URL \"{1}\". ".format(delta, selfURL))
	countDetector = labelDetector.saveTo(labelDetectorFilePath)
	if isinstance(countDetector, int):
		print("Successfully wrote {0} package name(s) of the detector label to the file \"{1}\". ".format(countDetector, labelDetectorFilePath))
	else:
		print("Failed to write the package name(s) of the detector label to the file \"{0}\" due to {1}. ".format(labelDetectorFilePath, repr(countDetector)))
	
	# Update the application label #
	delta, d = labelApplication.updateFromFiles(labelApplicationFilePath)
	if d:
		flag = False
		print("Updated {0} package name(s) of the application label from the file \"{1}\" with the following exception(s). ".format(delta, labelApplicationFilePath))
		for key, value in d.items():
			print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
	else:
		print("Successfully updated {0} package name(s) of the application label from the file \"{1}\". ".format(delta, labelApplicationFilePath))
	delta, d = labelApplication.updateFromURLs(selfURL, isDesktop = True)
	if d:
		flag = False
		print("Updated {0} package name(s) of the application label from the URL \"{1}\" with the following exception(s). ".format(delta, selfURL))
		for key, value in d.items():
			print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
	else:
		print("Successfully updated {0} package name(s) of the application label from the URL \"{1}\". ".format(delta, selfURL))
	countApplication = labelApplication.saveTo(labelApplicationFilePath)
	if isinstance(countApplication, int):
		print("Successfully wrote {0} package name(s) of the application label to the file \"{1}\". ".format(countApplication, labelApplicationFilePath))
	else:
		print("Failed to write the package name(s) of the application label to the file \"{0}\" due to {1}. ".format(labelApplicationFilePath, repr(countApplication)))
	
	# Update the system label #
	delta, d = labelSystem.updateFromFiles(labelSystemFilePath)
	if d:
		flag = False
		print("Updated {0} package name(s) of the system label from the file \"{1}\" with the following exception(s). ".format(delta, labelSystemFilePath))
		for key, value in d.items():
			print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
	else:
		print("Successfully updated {0} package name(s) of the system label from the file \"{1}\". ".format(delta, labelSystemFilePath))
	countSystem = labelSystem.saveTo(labelSystemFilePath)
	if isinstance(countSystem, int):
		print("Successfully wrote {0} package name(s) of the system label to the file \"{1}\". ".format(countSystem, labelSystemFilePath))
	else:
		print("Failed to write the package name(s) of the system label to the file \"{0}\" due to {1}. ".format(labelSystemFilePath, repr(countSystem)))
	
	# Update the Tricky Store Exclusions #
	delta, d = trickyStoreTargetExclusions.updateFromFiles(trickyStoreTargetExclusionFilePath)
	if d:
		flag = False
		print("Updated {0} package name(s) of Tricky Store target exclusions from the file \"{1}\" with the following exception(s). ".format(delta, trickyStoreTargetExclusionFilePath))
		for key, value in d.items():
			print("\t\"{0}\" -> {1}".format(key, repr(value) if isinstance(value, BaseException) else value))
	else:
		print("Successfully updated {0} package name(s) of Tricky Store target exclusions from the file \"{1}\". ".format(delta, trickyStoreTargetExclusionFilePath))
	trickyStoreTargetExclusionCount = trickyStoreTargetExclusions.saveTo(trickyStoreTargetExclusionFilePath)
	if isinstance(trickyStoreTargetExclusionCount, int):
		print("Successfully wrote {0} package name(s) of Tricky Store target exclusions to the file \"{1}\". ".format(trickyStoreTargetExclusionCount, trickyStoreTargetExclusionFilePath))
	else:
		print("Failed to write the package name(s) of Tricky Store target exclusions to the file \"{0}\" due to {1}. ".format(trickyStoreTargetExclusionFilePath, repr(trickyStoreTargetExclusionCount)))
	
	# Compute intersections #
	labelPairs = (
		(labelLRFP & labelDetector, "LRFP", "detector"), (labelLRFP & labelApplication, "LRFP", "application"), (labelLRFP & labelSystem, "LRFP", "system"), 
		(labelDetector & labelApplication, "detector", "application"), (labelDetector & labelSystem, "detector", "system"), (labelApplication & labelSystem, "application", "system")
	)
	for intersection, labelLeft, labelRight in labelPairs:
		if intersection:
			flag = False
			intersectionCount = len(intersection)
			print("There {0} in the intersection of the {1} and the {2} labels. \n\t{3}".format(			\
				("are {0} packageNames" if intersectionCount > 1 else "is {0} package").format(intersectionCount), 	\
				labelLeft, labelRight, intersection.getBytes(prefix = b"\t")					\
			))
	
	# Update the Web UI #
	if not (compress(webrootFolderPath, webrootFilePath, extensionsExcluded) and updateSHA512(srcFolderPath)):
		flag = False
	
	# Git Push #
	if flag:
		try:
			choice = input("Would you like to upload the files to GitHub via ``git`` [Yn]? ").upper() not in ("N", "NO", "0", "F", "FALSE")
		except:
			choice = True
		if choice:
			flag = gitPush(actionAFilePath, actionBFilePath)
	
	# Exit #
	errorLevel = EXIT_SUCCESS if flag else EXIT_FAILURE
	print("Please press the enter key to exit ({0}). ".format(errorLevel))
	try:
		input()
	except:
		print()
	print()
	return errorLevel



if "__main__" == __name__:
	exit(main())