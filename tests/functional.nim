## Nim HTTP Authentication and Authorization
## Functional tests. HTTP headers are mocked
## Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
## Released under LGPLv3 License, see LICENSE file

import unittest,
  httpcore,
  strutils,
  os

import httpauthpkg/base

import httpauth

when not defined(mock_send_email):
  {.error: "set -d:mock_send_email".}

from httpauthpkg/mailer import mock_email_spool

if paramCount() != 1:
  echo "URL param required"
  quit(1)
let db_uri = paramStr(1)

const
  test_basedir = "/tmp/test_httpauth/functional"
  test_admin_pwd = "hunter123"

proc pick_builtin_backend(db_uri: string): HTTPAuthBackend =
  let db_engine_name = db_uri.split("://")[0]
  case db_engine_name:
  of "sqlite":
    result = newSQLBackend(db_uri=db_uri)
  of "mysql":
    result = newSQLBackend(db_uri=db_uri)
  of "postgres":
    result = newSQLBackend(db_uri=db_uri)
  of "etcd":
    when defined(etcd):
      result = newEtcdBackend(db_uri=db_uri)
  of "redis":
    when defined(redis):
      result = newRedisBackend(db_uri=db_uri)
  of "mongodb":
    when defined(mongodb):
      result = newMongoDbBackend(db_uri=db_uri)

let backend = pick_builtin_backend(db_uri)


proc accept_cookie(headers: HttpHeaders) =
  ## Simulate client receiving Set-Cookie
  let c = headers["Set-Cookie"]
  headers.clear()
  headers.add("Cookie", c)


suite "functional simple " & db_uri:

  setup:
    backend.purge_all_tables()
    var aaa = newHTTPAuth("localhost", backend)
    var headers = newHttpHeaders()
    aaa.headers_hook(headers)

  teardown:
    backend.purge_all_tables()
    #aaa.shutdown()

  test "user is anonymous":
    assert aaa.is_user_anonymous() == true

  test "login inexistent user":
    expect LoginError:
      aaa.login("user1", "hunter123")

  #  aaa.login("user1", "hunter123")
  test "load datastore from disk":
    # init datastore
    #aaa.initialize_admin_user(password=test_admin_pwd)
    #FIXME
    # create new instance
    #let backend = newSQLBackend(test_basedir)
    #let aaa2 = newHTTPAuth("localhost", backend)
    #TODO check
    discard

  test "create user":
    #assert backend.count_users() == 0
    expect AuthError:
      aaa.create_user("user1", "hunter123")

import strutils

suite "functional " & db_uri:

  ## The following tests are not independent from each other!

  backend.purge_all_tables()
  var aaa = newHTTPAuth("localhost", backend)
  var headers = newHttpHeaders()
  aaa.headers_hook(headers)

  test "initialize admin user":
    assert backend.count_users() == 0
    assert backend.count_roles() == 0
    aaa.initialize_admin_user(password=test_admin_pwd)
    assert backend.count_roles() == 1
    let admin = backend.get_user("admin")
    assert admin.role == "admin"
    assert admin.hash != ""
    assert backend.count_users() == 1

  test "login":
    expect LoginError:
      aaa.login("admin", "wrong password")

    aaa.login("admin", test_admin_pwd)
    headers.accept_cookie()

    assert aaa.is_user_anonymous() == false

  test "create role":
    aaa.create_role("user", 50)
    assert backend.count_roles() == 2

  test "create user":
    aaa.create_user("user1", "pwd1", role="user")
    assert backend.count_users() == 2

  test "delete user":
    aaa.delete_user("user1")
    assert backend.count_users() == 1

  test "update role":
    var r = backend.get_role("user")
    r.level = 51
    assert backend.get_role("user").level == 50
    backend.set_role(r)
    assert backend.get_role("user").level == 51

  test "delete role":
    assert backend.count_roles() == 2
    aaa.delete_role("user")
    assert backend.count_roles() == 1

  test "create role":
    aaa.create_role("user", 50)
    assert backend.count_roles() == 2

  test "logout":
    aaa.logout()
    assert headers["set-cookie"] == "localhost=; Domain=localhost; " &
      "Expires=Thu, 01-Jan-1970 00:00:01 GMT; secure; HttpOnly"
    headers.clear()

  test "send registration email":
    assert mock_email_spool.len == 0
    aaa.register("user2", "pass2", "user2@example.com", description="Test user")
    assert mock_email_spool.len == 1
    assert mock_email_spool[0].sender == "localhost"
    assert mock_email_spool[0].rcpt == @["user2@example.com"]
    let msg = mock_email_spool[0].msg
    assert "http://localhost:8080/validate_registration" in msg
    assert "Your email address is: user2@example.com" in msg
    assert "Your role will be: user." in msg

    # mock_email_spool is not reset here: it will be used in the next tests

  test "list pending registrations":
    var cnt = 0
    for u in aaa.list_pending_registrations():
      cnt.inc
    assert cnt == 1

  test "validate_registration":
    let msg = mock_email_spool[0].msg
    mock_email_spool = @[]
    let reg_code_pos = msg.find("validate_registration/")
    let reg_code = msg[(reg_code_pos+22)..^1].split('"')[0]
    assert reg_code.len > 50

    assert backend.count_users() == 1
    aaa.validate_registration(reg_code)
    assert backend.count_users() == 2

  test "login, logout new user":
    aaa.login("user2", "pass2")
    aaa.logout()

  test "send password reset email by name":
    expect AuthError:
      aaa.send_password_reset_email()

    expect AuthError:
      aaa.send_password_reset_email(username="not_a_valid_user")

    aaa.send_password_reset_email(username="user2")
    assert mock_email_spool.len == 1
    assert mock_email_spool[0].sender == "localhost"
    # mock_email_spool is not reset here: it will be used in the next test

  test "reset password":
    #assert mock_email_spool[0].rcpt == @["user2@example.com"]
    let msg = mock_email_spool[0].msg
    mock_email_spool = @[]
    assert "http://localhost:8080/reset_password" in msg
    let res_code_pos = msg.find("reset_password/")
    let res_code = msg[(res_code_pos+15)..^1].split('"')[0]

    aaa.reset_password(res_code, "new_pass")

  test "login, logout user using new password":
    expect LoginError:
      aaa.login("user2", "pass2")

    aaa.login("user2", "new_pass")
    aaa.logout()

  test "send password reset email by email":
    expect UserNotFoundError:
      aaa.send_password_reset_email(email_addr="BOGUS@example.com")

    expect AuthError:
      #FIXME expect UserNotFoundError:
      # correct user but incorrect email addr
      aaa.send_password_reset_email(username="user2",
        email_addr="BOGUS@example.com")

    expect UserNotFoundError:
      # incorrect user but correct email addr
      aaa.send_password_reset_email(username="user2BOGUS",
        email_addr="user2@example.com")

    aaa.send_password_reset_email(email_addr="user2@example.com")
    assert mock_email_spool.len == 1
    mock_email_spool = @[]

  test "list users":
    var cnt = 0
    for u in aaa.list_users():
      cnt.inc
    assert cnt == 2

  test "list roles":
    var cnt = 0
    for r in aaa.list_roles():
      cnt.inc
    assert cnt == 2



    #[
    TODO:
    list_users
    list_roles
    purge_expired_regs
    argon2
    hash_scrypt()  .... verify()
    ]#



  backend.purge_all_tables()
  #aaa.shutdown()


import base64

suite "base64url":
  test "encode, decode":
    discard
    for i in 0..20:
      let orig = repeat('x', i).encode()
      let t = orig.strip(false, true, {'='})
      let padding = (4 - t.len mod 4) mod 4
      let v = t & repeat('=', padding)
      assert v == orig
