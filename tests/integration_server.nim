## Nim HTTP Authentication and Authorization - demo webapp
## Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
## Released under LGPLv3 License, see LICENSE file

## WARNING: Remember to filter user input to prevent XSS, SQL injections and similar attacks.

import asyncdispatch,
  json,
  jester,
  logging,
  strutils

import tests/integration_test_params
import httpauth

const
  main_page = slurp("./tests/demo_main_page.html")

let backend = newSQLBackend(db_uri=db_uri)
var auth = newHTTPAuth("localhost", backend)

auth.initialize_admin_user(password=test_admin_password)

routes:
  get "/":
    ## Serve forms
    resp main_page

  post "/login":
    ## Perform login
    #auth.headers_hook(request.headers)
    try:
      auth.login(@"username", @"password")
      # move set-cookie to right place - FIXME
      #response.data[2]["Set-Cookie"] = request.headers["set-cookie"]
      resp "Success"
    except LoginError:
      resp "Failed"

  get "/logout":
    ## Logout
    auth.headers_hook(request.headers)
    try:
      auth.logout()
      # move set-cookie to right place - FIXME
      if request.headers.hasKey("set-cookie"):
        echo repr request.headers["set-cookie"]
      #setCookie(request.headers["set-cookie"])
      resp "Success"
    except AuthError:
      resp "Failed"

  get "/is_user_anonymous":
    auth.headers_hook(request.headers)
    resp if auth.is_user_anonymous(): "True" else: "False"

  post "/register":
    ## Send registration email
    auth.headers_hook(request.headers)
    auth.register(@"username", @"password", @"email_address")
    resp "Please check your mailbox"

  post "/validate_registration/@registration_code":
    ## Validate registration, create user account
    auth.headers_hook(request.headers)
    auth.validate_registration(@"registration_code")
    resp """Thanks. <a href="/login">Go to login</a>"""

  post "/reset_password":
    ## Send out password reset email
    auth.headers_hook(request.headers)
    auth.send_password_reset_email(username = @"username", email_addr = @"email_address")
    resp "Please check your mailbox."

  get "/change_password/:reset_code":
    ## Show password change form
    ## FIXME resp dict(reset_code=reset_code)
    discard

  post "/change_password":
    ## Change password
    auth.headers_hook(request.headers)
    auth.reset_password(@("reset_code"), @("password"))
    resp """Thanks. <a href="/login">Go to login</a>"""

  get "/private":
    ## Only authenticated users can see this
    auth.headers_hook(request.headers)
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
    auth.headers_hook(request.headers)
    auth.require(role="admin")
    # resp dict( current_user=auth.current_user, users=auth.list_users(), roles=auth.list_roles())


  post "/create_user":
    auth.headers_hook(request.headers)
    try:
      auth.create_user(@"username", @"password", @"role")
      resp $( %* {"ok": true, "msg": ""})
    except AuthError:
      let r = %* {"msg": getCurrentExceptionMsg(), "ok": false}
      resp $r


  post "/delete_user":
    auth.headers_hook(request.headers)
    try:
      auth.delete_user(@("username"))
      resp $( %* {"ok": true, "msg": ""})
    except AuthError:
      let r = %* {"msg": getCurrentExceptionMsg(), "ok": false}
      resp $r


  post "/create_role":
    auth.headers_hook(request.headers)
    let level = @"level".parseInt
    try:
      auth.create_role(@("role"), level)
      resp $( %* {"ok": true, "msg": ""})
    except AuthError:
      let r = %* {"msg": getCurrentExceptionMsg(), "ok": false}
      resp $r


  post "/delete_role":
    auth.headers_hook(request.headers)
    try:
      auth.delete_role(@("role"))
      resp $( %* {"ok": true, "msg": ""})
    except AuthError:
      let r = %* {"msg": getCurrentExceptionMsg(), "ok": false}
      resp $r

  get "/list_roles":
    auth.headers_hook(request.headers)
    var msg = ""
    for r in auth.list_roles():
      msg.add r.name & ","
    resp msg



runForever()

