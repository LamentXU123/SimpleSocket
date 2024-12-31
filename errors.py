# -*- coding:utf-8 -*-
# @FileName  :errors.py
# @Time      :2023/11/22 12:37:43
# @Author    :D0WE1L1N
'''
Definate all the errors
'''
class MessageLengthError(Exception):
    def __init__(self, message) -> None:
        self.message = message

class PasswordError(Exception):
    def __init__(self, message) -> None:
        self.message = message