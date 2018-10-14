## Nim HTTP Authentication and Authorization - SQLite Backend functional tests
## Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
## Released under LGPLv3 License, see LICENSE file

import unittest,
  times,
  strutils

from os import removeFile, paramCount, paramStr
import httpauthpkg/base
import httpauthpkg/sql_backend

if paramCount() != 1:
  echo "URL param required"
  quit(1)
let db_uri = paramStr(1)

suite "SQL test $#" % db_uri:

  let t = 1234567890.fromUnix.utc()

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

    block:
      let user = b.get_user("foo")
      assert user.username == u.username
      assert user.role == u.role
      assert user.description == u.description
      assert user.email_addr == u.email_addr
      assert user.hash == u.hash
      assert user.creation_date == u.creation_date
      assert user.last_login == u.last_login

    assert b.list_users().len == 1
    for user in b.list_users():
      assert user.username == u.username
      assert user.role == u.role
      assert user.description == u.description
      assert user.email_addr == u.email_addr
      assert user.hash == u.hash
      assert user.creation_date == u.creation_date
      assert user.last_login == u.last_login

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

    block:
      let role = b.get_role("foo")
      assert role.name == r.name
      assert role.level == r.level

    assert b.list_roles().len == 1
    for role in b.list_roles():
      assert role.name == r.name
      assert role.level == r.level

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

    assert b.list_pending_registrations().len == 1
    for pr in b.list_pending_registrations():
      assert pr.username == u.username
      assert pr.role == u.role
      assert pr.email_addr == u.email_addr
      assert pr.description == u.description
      assert pr.hash == u.hash
      assert pr.creation_date == u.creation_date

    block:
      let pr = b.get_pending_registration("reg_code_xyz")
      assert pr.username == u.username
      assert pr.role == u.role
      assert pr.email_addr == u.email_addr
      assert pr.description == u.description
      assert pr.hash == u.hash
      assert pr.creation_date == u.creation_date

    b.delete_pending_registration("reg_code_xyz")
    assert b.count_pending_registrations() == 0
    assert b.list_pending_registrations().len == 0
