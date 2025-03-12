#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2025/2/19
# @Author  : LukasEpheser
# @File    : phpparser.py

from front_analysise.modules.parser.baseparse import BaseParser

import os
import re

PHP_SANITIZER = [
    "htmlspecialchars",  # XSS
    "strlen",  # Misc., e.g., Buffer Overflows
    "mysql_real_escape_string",  # SQL-Injection
    "preg_replace",  # Misc., e.g., Path Traversal
    "str_replace",  # Misc., e.g., Path Traversal
    "json_encode",  # Misc., e.g., JSON Injection
    "strip_tags",  # Code (HTML, JS, PHP) Injection
    "filter_var",  # Misc, e.g., XSS or SQL-Injection
    "filter_input",  # Misc, e.g., XSS or SQL-Injection
    "escapeshellarg",  # Command Line Injection
    "escapeshellcmd",  # Command Line Injection
]

# Some $_SERVER variables are not user-controllable - we filter accesses to them.
# Source: https://stackoverflow.com/questions/6474783/which-server-variables-are-safe
PHP_SERVER_FILTER = [
    "GATEWAY_INTERFACE",
    "SERVER_ADDR",
    "SERVER_SOFTWARE",
    "DOCUMENT_ROOT",
    "SERVER_ADMIN",
    "SERVER_SIGNATURE",
    "HTTPS",
    "REQUEST_TIME",
    "REMOTE_ADDR",
    "REMOTE_HOST",
    "REMOTE_PORT",
    "SERVER_PROTOCOL",
    "HTTP_HOST",
    "SERVER_NAME",
    "SCRIPT_FILENAME",
    "SERVER_PORT",
    "SCRIPT_NAME",
]

# Parses PHP files to extract access keys of user-controllable superglobal arrays.
# If a valid access key is found, the module passes it to subsequent data flow analysis.
class PHPParser(BaseParser):

    def __init__(self, filepath):
        BaseParser.__init__(self, filepath)

    def analysise(self):
        if os.path.isfile(self.fpath):
            content = ""
            self.log.debug("PHP: Start analysis for file {}".format(self.fpath))
            with open(self.fpath, "rb") as f:
                content = f.read().decode("utf-8", "ignore")

            self.get_keywords(content)

    def get_keywords(self, code):
        # Matches accesses to sensitive global PHP arrays.
        # Group 0: matched line
        # Group 1 (optional): assigned variable
        # Group 2 (optional): wrapper function around access
        # Group 3: global array name
        # Group 4: key
        global_array_matches = re.findall(
            r'((\$\w+)?\s*=?\s*(\b[\w]*\s*\((?:[^)]*?))?\s*\$\_(GET|POST|SERVER|COOKIE|FILES|REQUEST)\[["\']([\w\.]*?)["\']\])',
            code,
        )

        # All matches subject to filtering.
        matches = [
            {
                "matched_line": match[0],
                "assigned_parameter": match[1],
                "wrapping_function": match[2],
                "superglobal_array": match[3],
                "key": match[4],
                "sanitized_by": None,
            }
            for match in global_array_matches
        ]

        # De-duped keywords passed to SaTC.
        keywords = set()

        # Start filtering...
        for match in matches:
            self.log.debug(
                'PHP: Found access to array "{}" with key "{}"'.format(match["superglobal_array"], match["key"])
            )

            # Check if access to $_SERVER is user-controllable.
            if match["superglobal_array"] == "SERVER" and match["key"] in PHP_SERVER_FILTER:
                self.log.debug(
                    'PHP: Filter keyword "{}": accessed $_SERVER variable not controllable'.format(match["key"])
                )
                match["sanitized_by"] = "accessed $_SERVER variable not controllable"
                continue

            # Check if access or assigned variable is passed into sanitizer functions.
            for func in PHP_SANITIZER:
                if func in match["wrapping_function"]:
                    self.log.debug('PHP: Filter keyword "{}": wrapped in sanitizer {}'.format(match["key"], func))
                    match["sanitized_by"] = "access wrapped in sanitizer " + func
                    break

                if match["assigned_parameter"]:
                    pattern = r"\b" + func + r"\s*\(([^)]*?)" + re.escape(match["assigned_parameter"]) + r"([^)]*?)\)"
                    matches = re.findall(pattern, code)

                    if matches:
                        self.log.debug('PHP: Filter keyword "{}": passed to sanitizer {}'.format(match["key"], func))
                        match["sanitized_by"] = "assigned var passed to sanitizer " + func
                        break

            keywords.add(match["key"])

        for keyword in keywords:
            self.log.debug('PHP: Pass keyword "{}" to SaTC'.format(keyword))
            self._get_keyword(keyword, check=2)


if __name__ == "__main__":
    pass
