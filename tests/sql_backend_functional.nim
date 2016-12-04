#
## Nim HTTP Authentication and Authorization - SQLite Backend functional tests
#
# Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file

import unittest,
  times,
  strutils

from os import removeFile, paramCount, paramStr
import base
import sql_backend

if paramCount() != 1:
  echo "URL param required"
  quit(1)
let db_uri = paramStr(1)

suite "SQL test $#" % db_uri:

  let t = 1234567890.fromSeconds.getGMTime()

  setup:
    let db_engine_name = db_uri.split("://")[0]
    let dbname = db_uri.split("://")[1]
    if db_engine_name == "sqlite" and dbname != ":memory:":
      echo "removing SQLite file ", dbname
      removeFile(dbname)

    let b = newSQLBackend(db_uri)
    b.purge_all_tables()

  teardown:
    b.shutdown()

  test "user":
    assert b.count_users() == 0
    var u = User(username:"foo", role:"editor", email_addr:"e@ma.il",
      description:"mydesc", creation_date:t, last_login:t, hash:"123")
    expect UserNotFoundError:
      discard b.get_user("foo")

    b.set_user(u)
    assert b.count_users() == 1

    u.description = "my new desc"
    b.set_user(u)
    assert b.count_users() == 1

    assert b.get_user("foo") == u

    var cnt = 0
    for user in b.list_users():
      assert user == u
      cnt.inc
    assert cnt == 1

    b.delete_user("foo")
    assert b.count_users() == 0

  test "role":
    var r = Role(name:"foo", level:50)
    assert b.count_roles() == 0
    expect RoleNotFoundError:
      discard b.get_role("foo")

    b.set_role(r)
    assert b.count_roles() == 1

    r.level = 55
    b.set_role(r)
    assert b.count_roles() == 1

    assert b.get_role("foo") == r

    var cnt = 0
    for role in b.list_roles():
      assert role == r
      cnt.inc
    assert cnt == 1

    b.delete_role("foo")
    assert b.count_roles() == 0

  test "pending_registration":
    var u = PendingRegistration(username:"user1", role:"editor",
      email_addr:"e@ma.il", description:"mydesc", creation_date:t, hash:"123")
    assert b.count_pending_registrations() == 0
    expect PendingRegistrationNotFoundError:
      discard b.get_pending_registration("reg_code_xyz")

    b.set_pending_registration("reg_code_xyz", u)
    assert b.count_pending_registrations() == 1

    u.description = "my new desc"
    b.set_pending_registration("reg_code_xyz", u)
    assert b.count_pending_registrations() == 1

    assert b.get_pending_registration("reg_code_xyz") == u

    var cnt = 0
    for pending_registration in b.list_pending_registrations():
      assert pending_registration == u
      cnt.inc
    assert cnt == 1

    b.delete_pending_registration("reg_code_xyz")
    assert b.count_pending_registrations() == 0


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

  #test "parse_uri":
  #  let uri = parse_uri("mysql://1.22.33.250:123/dbname")

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