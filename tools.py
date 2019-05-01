#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: Homer
# Date: 2018-05-24
# Version: 0.1
# ELK

import ast

class Tools:
    def str2list(self, _x):
        if type(_x) == str:
            x = ast.literal_eval(_x)
            return x
        else:
            return _x


    def isna_list(self, _list):
        if not _list:
            return False
        else:
            return True