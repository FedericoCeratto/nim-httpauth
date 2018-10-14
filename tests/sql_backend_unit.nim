## Nim HTTP Authentication and Authorization - SQL Backend unit tests
## Copyright 2018 Federico Ceratto <federico.ceratto@gmail.com>
## Released under LGPLv3 License, see LICENSE file

import unittest

import httpauthpkg/base
import httpauthpkg/sql_backend

suite "parse_uri":
  test "parse_uri":
    let uri = parse_uri("mysql://user:pass@localhost/dbname")
    assert uri.engine == "mysql"
    assert uri.user == "user"
    assert uri.password == "pass"
    assert uri.hostname == "localhost"
    assert uri.schema == "dbname"

  test "parse_uri":
    let uri = parse_uri("mysql://user@localhost:123/dbname")

  test "parse_uri":
    let uri = parse_uri("mysql://localhost/dbname")

  test "parse_uri":
    let uri = parse_uri("mysql://localhost:123/dbname")
    check uri.hostname == "localhost"

  test "parse_uri":
    let uri = parse_uri("mysql://127.0.0.1/dbname")
    check uri.hostname == "127.0.0.1"

  test "parse_uri":
    let uri = parse_uri("mysql://127.0.0.1:3306/dbname")
    check uri.hostname == "127.0.0.1"

  test "parse_uri":
    let uri = parse_uri("mysql://127tricky:3306/dbname")
    check uri.hostname == "127tricky"

  test "parse_uri":
    let uri = parse_uri("mysql://127.tricky:3306/dbname")
    check uri.hostname == "127.tricky"

  test "parse_uri":
    let uri = parse_uri("mysql://user@localhost:123/dbname")

  test "parse_uri":
    let uri = parse_uri("mysql://user:pass@localhost:123/dbname")

  test "parse_uri":
    let uri = parse_uri("mysql://user:pass@localhost/dbname")

  test "parse_uri":
    let uri = parse_uri("mysql://user:pass@localhost:123/dbname")

  test "parse_uri":
    let uri = parse_uri("sqlite://:memory:")

  test "parse_uri":
    let uri = parse_uri("sqlite:///tmp/foo.sqlite3")
