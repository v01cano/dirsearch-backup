# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Mauro Soria

import threading

import urllib.error
import urllib.parse
import urllib.request
import re
from lib.utils.FileUtils import File
from thirdparty.oset import *


class Dictionary(object):


    def __init__(self, paths, extensions, suffixes=None, prefixes=None, lowercase=False, uppercase=False, forcedExtensions=False, noDotExtensions=False, excludeExtensions=[], url=''):
        self.entries = []
        self.currentIndex = 0
        self.condition = threading.Lock()
        self._extensions = extensions
        self._prefixes = prefixes
        self._suffixes = suffixes
        self._paths = paths
        self._forcedExtensions = forcedExtensions
        self._noDotExtensions = noDotExtensions
        self._excludeExtensions = excludeExtensions
        self.lowercase = lowercase
        self.uppercase = uppercase
        self.url = url
        self.dictionaryFiles = [File(path) for path in self.paths]
        self.generate()

    @property
    def extensions(self):
        return self._extensions

    @extensions.setter
    def extensions(self, value):
        self._extensions = value

    @property
    def paths(self):
        return self._paths

    @paths.setter
    def paths(self, paths):
        self._paths = paths

    @classmethod
    def quote(cls, string):
        return urllib.parse.quote(string, safe=":/~?%&+-=$!@^*()[]{}<>;'\"|\\,._")
    """backup scan"""
    def getdictFromUrl(self):
        lines = []
        domainname = re.sub("https://", '', self.url)
        domainname = re.sub("http://", '', domainname)
        domainname = re.sub("/", '', domainname)
        line = domainname.split(':')
        line = str(line[0]).split('.')
        domainname2=""
        for i in line:
            domainname2 = domainname2+i
        for i in range(len(line)-1):
            lines.append("%s.zip" % line[i])
            lines.append("%s.tar.gz" % line[i])
            lines.append("%s.rar" % line[i])
            lines.append("%s.tar" % line[i])
            lines.append("%s.sql" % line[i])
        lines.append("%s.zip" % domainname)
        lines.append("%s.tar.gz" % domainname)
        lines.append("%s.rar" % domainname)
        lines.append("%s.tar" % domainname)
        lines.append("%s.sql" % domainname)
        lines.append("%s.zip" % domainname2)
        lines.append("%s.tar.gz" % domainname2)
        lines.append("%s.rar" % domainname2)
        lines.append("%s.tar" % domainname2)
        lines.append("%s.sql" % domainname2)
        for j in range(len(line)-1):
            for i in range(len(line)-1):
                lines.append("{0}{1}.zip".format(line[j], line[i]))
                lines.append("{0}{1}.tar.gz".format(line[j], line[i]))
                lines.append("{0}{1}.rar".format(line[j], line[i]))
                lines.append("{0}{1}.tar".format(line[j], line[i]))
                lines.append("{0}{1}.sql".format(line[j], line[i]))
        for i in range(2000, 2021):
            lines.append("%s.zip" % i)
            lines.append("%s.tar.gz" % i)
            lines.append("%s.rar" % i)
            lines.append("%s.tar" % i)
            lines.append("%s.sql" % i)
        for i in range(2000, 2021):
            lines.append("{0}{1}.zip".format(domainname2, i))
            lines.append("{0}{1}.tar.gz".format(domainname2, i))
            lines.append("{0}{1}.rar".format(domainname2, i))
            lines.append("{0}{1}.tar".format(domainname2, i))
            lines.append("{0}{1}.sql".format(domainname2, i))
        for j in range(len(line)-1):
            for i in range(2000, 2021):
                lines.append("{0}{1}.zip".format(line[j], str(i)))
                lines.append("{0}{1}.tar.gz".format(line[j], str(i)))
                lines.append("{0}{1}.rar".format(line[j], str(i)))
                lines.append("{0}{1}.tar".format(line[j], str(i)))
                lines.append("{0}{1}.sql".format(line[j], str(i)))
        return lines
    """
    Dictionary.generate() behaviour

    Classic dirsearch wordlist:
      1. If %EXT% keyword is present, append one with each extension REPLACED.
      2. If the special word is no present, append line unmodified.

    Forced extensions wordlist (NEW):
      This type of wordlist processing is a mix between classic processing
      and DirBuster processing.
          1. If %EXT% keyword is present in the line, immediately process as "classic dirsearch" (1).
          2. If the line does not include the special word AND is NOT terminated by a slash,
            append one with each extension APPENDED (line.ext) and ONLYE ONE with a slash.
          3. If the line does not include the special word and IS ALREADY terminated by slash,
            append line unmodified.
    """

    def generate(self):
        reext = re.compile('\%ext\%', re.IGNORECASE).sub
        reextdot = re.compile('\.\%ext\%', re.IGNORECASE).sub
        exclude = re.findall
        result = []


        # Enable to use multiple dictionaries at once
        for dictFile in self.dictionaryFiles:
            for line in list(dict.fromkeys(dictFile.getLines())):
                if line.startswith("/"):
                    line = line[1:]
                
                # Check if the line is having the %NOFORCE% keyword
                if "%noforce%" in line.lower():
                    noforce = True
                else:
                    noforce = False

                # Skip comments
                if line.lstrip().startswith("#"):
                    continue

                # Skip if the path is containing excluded extensions
                if len(self._excludeExtensions):
                    matched = False
                    
                    for excludeExtension in self._excludeExtensions:
                        if len(exclude("." + excludeExtension, line)):
                            matched = True
                            break
                            
                    if matched:
                        continue

                # Classic dirsearch wordlist processing (with %EXT% keyword)
                if "%ext%" in line.lower():
                    for extension in self._extensions:
                        if self._noDotExtensions:
                            newline = reextdot(extension, line)

                        else:
                            newline = line
                            
                        newline = reext(extension, newline)

                        quote = self.quote(newline)
                        result.append(quote)

                # If forced extensions is used and the path is not a directory ... (terminated by /)
                # process line like a forced extension.
                elif self._forcedExtensions and not line.rstrip().endswith("/") and not noforce:
                    quoted = self.quote(line)

                    for extension in self._extensions:
                        # Why? Check https://github.com/maurosoria/dirsearch/issues/70
                        if extension.strip() == '':
                            result.append(quoted)
                        else:
                            result.append(quoted + ('' if self._noDotExtensions else '.') + extension)

                    if quoted.strip() != '':
                        result.append(quoted)
                        result.append(quoted + "/")

                # Append line unmodified.
                else:
                    result.append(self.quote(line))
                    
        # Adding prefixes for finding private pages etc
        if self._prefixes:
            for res in list(dict.fromkeys(result)):
                for pref in self._prefixes:
                    if not res.startswith(pref): 
                        result.append(pref + res)

        # Adding suffixes for finding backups etc
        if self._suffixes:
            for res in list(dict.fromkeys(result)):
                if not res.rstrip().endswith("/"):
                    for suff in self._suffixes:
                        result.append(res + suff)
		# oset library provides inserted ordered and unique collection.				
        if 1:        
            BackupDict = self.getdictFromUrl()
            print("[+] Base Dict length: " + str(len(result)))
            result = result + BackupDict
            print("[+] Backup Dict length: " + str(len(BackupDict)))
            #print(result)

        if self.lowercase:
            self.entries = list(dict.fromkeys(map(lambda l: l.lower(), result)))
            
        elif self.uppercase:
            self.entries = list(dict.fromkeys(map(lambda l: l.upper(), result)))

        else:
            self.entries = list(dict.fromkeys(result))

        del result

    def regenerate(self):
        self.generate()
        self.reset()

    def nextWithIndex(self, basePath=None):
        self.condition.acquire()

        try:
            result = self.entries[self.currentIndex]

        except IndexError:
            self.condition.release()
            raise StopIteration

        self.currentIndex = self.currentIndex + 1
        currentIndex = self.currentIndex
        self.condition.release()
        return currentIndex, result

    def __next__(self, basePath=None):
        _, path = self.nextWithIndex(basePath)
        return path

    def reset(self):
        self.condition.acquire()
        self.currentIndex = 0
        self.condition.release()

    def __len__(self):
        return len(self.entries)
