
## Nim HTTP Authentication and Authorization
## Functional tests. HTTP headers are mocked
## Copyright 2019 Federico Ceratto <federico.ceratto@gmail.com>
## Released under LGPLv3 License, see LICENSE file

import unittest,
  strutils

from libsodium/sodium import crypto_pwhash_str_verify

import httpauthpkg/base

import httpauth

suite "hashing":
  test "password_pwhash_str":
    const pwd = "Correct Horse Battery Staple"
    let h = password_pwhash_str(pwd)
    check crypto_pwhash_str_verify(h, pwd) == true
    check crypto_pwhash_str_verify(h, pwd & "!") == false
    check password_needs_rehashing(h) == false
