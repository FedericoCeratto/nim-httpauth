
import os, osproc,
  unittest,
  strutils

import testclient

from integration_server import test_admin_password

const test_basedir = "/tmp/test_httpauth/integration"

suite "integration JSON":

  # Start integration test server
  #[
  let test_srv = startProcess("./tests/integration_server", options={})
  sleep(100)
  assert test_srv.running()
  echo "server ready"
  ]#

  let c = newHttpTestClient("http", "localhost:5000")
  const test_admin_password = "hunter123"

  setup:
    #if not test_srv.running(): fail()
    removeDir(test_basedir)
    #let backend = newJsonAuth(test_basedir)
    #let aaa = newHTTPAuth("localhost", backend)
    #assert test_srv.running()

  test "get /":
    #assert test_srv.running()
    var r = c.get("/")
    assert r.OK
    assert r.body.contains("username")

  test "fail login":
    var r = c.post("/login", {"username": "foo", "password": "bar"})
    assert r.body != "Success"
    # FIXME check cookie

  test "full test":
    checkpoint "login admin"

    var r = c.post("/login", {"username": "admin", "password": test_admin_password})
    echo ">" & r.body & "<"
    assert r.body == "Success"

    # FIXME check cookie


  #[
  test "login":
    var r = c.post("/login", {"username": "foo", "password": "bar"})
    echo r
    assert r.OK
    assert r.body == "Success"
    # FIXME check cookie
    # FIXME should fail
    #
  test "logout":
    var r = c.get("/logout")
    assert r.OK
    assert r.body == "Success"

  test "logout":
    var r = c.post("/logout", {:})
    assert r.OK
    assert r.body == "Success"

  test "is_user_anonymous":
    var r = c.get("/is_user_anonymous")
    assert r.OK
    assert r.body == "False", r.body
    #F

  ]#

  # Stop integration test server
  #[
  while test_srv.running():
    if not test_srv.running(): break  # double take required
    echo "terminating..."
    test_srv.terminate()
    sleep(1)
  ]#
  echo "done"

