#
# Nim HTTP Authentication and Authorization - demo webapp
#
# Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file

import asyncdispatch,
  json,
  jester,
  logging,
  strutils

import httpauth

const
  main_page = slurp("./tests/demo_main_page.html")
  test_admin_password* = "hunter123"
  test_basedir* = "/tmp/test_httpauth/integration"

let backend = newJsonAuth(test_basedir)
var auth = newHTTPAuth("localhost", backend)

auth.initialize_admin_user(password=test_admin_password)

routes:
  get "/":
    ## Serve forms
    resp main_page

  post "/login":
    ## Perform login
    auth.headers_hook(request.headers)
    try:
      auth.login("", "")
      resp "Success"
    except LoginError:
      resp "Failed"

  get "/logout":
    ## Logout
    try:
      auth.logout()
      resp "Success"
    except AuthError:
      resp "Failed"

  post "/logout":
    ## Logout
    try:
      auth.logout()
      resp "Success"
    except AuthError:
      resp "Failed"

  get "/is_user_anonymous":
    resp if auth.is_user_anonymous(): "True" else: "False"

  post "/register":
    auth.register(@"username", @"password", @"email_address")
    resp "Please check your mailbox"

  post "/validate_registration/@registration_code":
    ## Validate registration, create user account
    auth.validate_registration(@"registration_code")
    resp """Thanks. <a href="/login">Go to login</a>"""

  post "/reset_password":
    ## Send out password reset email
    auth.send_password_reset_email(username = @"username", email_addr = @"email_address")
    resp "Please check your mailbox."

  get "/change_password/:reset_code":
    ## Show password change form
    ## FIXME resp dict(reset_code=reset_code)
    discard

  post "/change_password":
    ## Change password
    auth.reset_password(@("reset_code"), @("password"))
    resp """Thanks. <a href="/login">Go to login</a>"""

  get "/private":
    ## Only authenticated users can see this
    try:
      auth.require()
    except AuthError:
      resp "Sorry, you are not authorized."
    resp """Welcome! <a href="/admin">Admin page</a> <a href="/logout">Logout</a>"""

  #get "/restricted_download":
  #  ## Only authenticated users can download this file from ./public
  #  auth.require()
  #  resp bottle.static_file("static_file", root=".")

  get "/my_role":
    ## Show current user role
    auth.require()
    resp auth.current_user.role


  # # Admin-only pages

  get "/admin":
    ## Only admin users can see this
    auth.require(role="admin")
    # resp dict( current_user=auth.current_user, users=auth.list_users(), roles=auth.list_roles())


  post "/create_user":
    try:
      auth.create_user(@"username", @"role", @"password")
      resp $( %* {"ok": true, "msg": ""})
    except AuthError:
      let r = %* {"msg": getCurrentExceptionMsg(), "ok": true}
      resp $r


  post "/delete_user":
    try:
      auth.delete_user(@("username"))
      resp $( %* {"ok": true, "msg": ""})
    except AuthError:
      let r = %* {"msg": getCurrentExceptionMsg(), "ok": true}
      resp $r


  post "/create_role":
    let level = @"level".parseInt
    try:
      auth.create_role(@("role"), level)
      resp $( %* {"ok": true, "msg": ""})
    except AuthError:
      let r = %* {"msg": getCurrentExceptionMsg(), "ok": true}
      resp $r


  post "/delete_role":
    try:
      auth.delete_role(@("role"))
      resp $( %* {"ok": true, "msg": ""})
    except AuthError:
      let r = %* {"msg": getCurrentExceptionMsg(), "ok": true}
      resp $r




runForever()

