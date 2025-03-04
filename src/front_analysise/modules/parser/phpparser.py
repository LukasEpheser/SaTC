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
    "mysql_real_escape_string",  # SQL-Injection
    "preg_replace",  # Misc., e.g., Path Traversal
    "str_replace",  # Misc., e.g., Path Traversal
    "json_encode",  # Misc., e.g., JSON Traversal
    "strip_tags",  # Code (HTML, JS, PHP) Injection
    "filter_var",  # Misc, e.g., XSS or SQL-Injection
    "filter_input",  # Misc, e.g., XSS or SQL-Injection
    "escapeshellarg",  # Command Line Injection
    "escapeshellcmd",  # Command Line Injection
]

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
            r'((\$\w+)?\s*=?\s*(\b[\w]*\s*\((?:[^)]*?))?\s*\$\_(GET|POST|SERVER|COOKIE|FILES)\[["\']([\w\.]*?)["\']\])',
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

        for match in matches:
            self.log.debug('PHP: Found keyword "{}"'.format(match["key"]))

            # Check if access to $_SERVER is user-controllable.
            if match["superglobal_array"] == "SERVER" and match["key"] in PHP_SERVER_FILTER:
                self.log.debug(
                    'PHP: Filter keyword "{}": accessed $_SERVER variable not controllable'.format(match["key"])
                )
                match["sanitized_by"] = "accessed $_SERVER variable not controllable"
                continue

            # Check if assigned variable is passed into sanitizer functions.
            if match["assigned_parameter"]:
                for func in PHP_SANITIZER:
                    pattern = r"\b" + func + r"\s*\(([^)]*?)" + re.escape(match["assigned_parameter"]) + r"([^)]*?)\)"
                    matches = re.findall(pattern, code)

                    if matches:
                        self.log.debug('PHP: Filter keyword "{}": detected sanitizer {}'.format(match["key"], func))
                        match["sanitized_by"] = "passed to sanitizer " + func
                        break

            keywords.add(match["key"])

        for keyword in keywords:
            self.log.debug('PHP: Pass keyword "{}" to SaTC'.format(keyword))
            self._get_keyword(keyword, check=2)


if __name__ == "__main__":
    pass
