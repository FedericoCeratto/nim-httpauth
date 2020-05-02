## Nim HTTP Authentication and Authorization - end-to-end tests
## Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
## Released under LGPLv3 License, see LICENSE file

import json,
  os,
  osproc,
  streams,
  strutils,
  unittest

import testclient
from httpauthpkg/cookiejar import count, pprint

import integration_test_params

suite "integration JSON":

  # Prepare directory and start integration server
  createDir test_basedir
  if existsFile test_db_fname:
    removeFile test_db_fname
  let test_srv = startProcess("./tests/integration_server", options={})
  sleep(200)
  assert test_srv.running()

  var c = newHttpTestClient("http", "localhost:5000")

  setup:
    if not test_srv.running(): fail()

  test "get /":
    var r = c.get("/")
    check r.status == "200 OK"
    check r.body().contains("username")

  test "fail login":
    var r = c.post("/login", {"username": "foo", "password": "bar"})
    check r.body != "Success"
    check c.cookiejar.count == 0

  test "full test":
    check c.get("/is_user_anonymous").body == "True"
    check c.cookiejar.count == 0

  test "login admin":
    var r = c.post("/login", {"username": "admin", "password": test_admin_password})
    check r.body == "Success"
    check c.cookiejar.count == 1
    # c.cookiejar.pprint()

  test "admin is now logged in":
    check c.get("/is_user_anonymous").body == "False"

  test "logout":
    check c.get("/logout").body == "Success"
    check c.cookiejar.count == 0
    check c.get("/is_user_anonymous").body == "True"

  test "logout again":
    check c.get("/logout").body == "Success"
    check c.cookiejar.count == 0
    check c.get("/is_user_anonymous").body == "True"

  test "login admin again":
    var r = c.post("/login", {"username": "admin", "password": test_admin_password})
    check r.body == "Success"
    check c.cookiejar.count == 1

  test "access /private":
    check c.get("/private").body.contains("Welcome")

  test "access /my_role":
    check c.get("/my_role").body == "admin"

  test "access /admin":
    # FIXME
    echo c.get("/admin").body

  test "list roles":
    check c.get("/list_roles").body == "admin,"

  test "create role":
    var r = c.post("/create_role", {
      "role": "testrole",
      "level": "10",
    })
    let j = r.body.parseJson()
    check j["ok"].getBool == true

  test "list roles":
    let roles = c.get("/list_roles").body
    check (roles == "testrole,admin," or roles == "admin,testrole,")

  test "create user":
    var r = c.post("/create_user", {
      "username": "testuser",
      "role": "testrole",
      "password": "testuser_pass"
    })
    let j = r.body.parseJson()
    # FIXME
    echo j
    check j["ok"].getBool == true

  test "create user with inexistent role":
    var r = c.post("/create_user", {
      "username": "testuser",
      "role": "testrole_BOGUS",
      "password": "testuser_pass"
    })
    let j = r.body.parseJson()
    check j["ok"].getBool == false


  test "logout":
    check c.get("/logout").body == "Success"
    check c.cookiejar.count == 0

  test "login as new user":
    var r = c.post("/login", {"username": "testuser",
      "password": "testuser_pass"})
    check r.body == "Success"
    check c.cookiejar.count == 1

  test "create role from normal user":
    var r = c.post("/create_role", {
      "role": "testrole2",
      "level": "10",
    })
    let j = r.body.parseJson()
    #FIXME
    echo j
    check j["ok"].getBool == false

  test "create user from normal user":
    var r = c.post("/create_user", {
      "username": "testuser",
      "role": "testrole",
      "password": "testuser_pass"
    })
    let j = r.body.parseJson()
    check j["ok"].getBool == false





  # Stop integration test server
  while test_srv.running():
    if not test_srv.running(): break  # double take required
    echo "terminating..."
    test_srv.terminate()
    sleep(10)
  echo "--- server output ---"
  echo test_srv.outputStream().readAll()
  echo "------"
  echo "done"

