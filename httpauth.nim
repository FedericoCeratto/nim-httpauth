#
# Nim HTTP Authentication and Authorization
#
# Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file
#
# Based on https://github.com/FedericoCeratto/bottle-cork

import asyncdispatch,
  cookies,
  logging,
  httpcore,
  times,
  strutils

from strtabs import `[]`, hasKey
from times import utc, fromUnix

import libsodium/sodium
import libsodium/sodium_sizes

import httpauthpkg/[base,
  mailer,
  json_backend,
  sql_backend]

export newJsonBackend,
  newSQLBackend,
  HTTPAuthBackend,
  AuthError,
  LoginError

when defined(redis):
  import httpauthpkg/redis_backend
  export newRedisBackend

when defined(etcd):
  import httpauthpkg/etcd_backend
  export newEtcdBackend

when defined(mongodb):
  import httpauthpkg/mongodb_backend
  export newMongoDbBackend


const
  deleted_cookie_expiration_time = "Thu, 01 Jan 1970 00:00:00 GMT"
  cookie_expiration_time_fmt = "ddd, dd-mmm-yyyy HH:MM:SS GMT"
  admin_level = 100

type
  HashingAlgorithm* = enum
    Argon2, Scrypt

  HTTPAuth* = object of RootObj
    password_reset_timeout*: int
    domain*: string
    cookie_name*: string
    cookie_domain*: string
    session_key: string  # secret used for cookie crypto + sign
    https_only_cookies*: bool
    backend: HTTPAuthBackend
    mailer: Mailer
    headers: HttpHeaders

proc r*(e: typedesc, msg: string) =
  raise newException(e, msg)

# # Definitions

proc current_user*(self: HTTPAuth): User

# # Internals

import base64

proc safe_encode(i: string): string =
  ## URL-safe and Cookie-safe encoding
  base64.encode(i, safe=true).strip(false, true, {'='})

proc safe_decode(i: string): string =
  ## URL-safe and Cookie-safe decoding
  let padding =
    case (i.len mod 4)
    of 1: "==="
    of 2: "=="
    of 3: "="
    else: ""
  (i & padding)
    .replace('-', '+')
    .replace('_', '/')
    .decode()


# 4096 bytes cookie limit FIXME

# Crypto

proc password_pwhash_str*(password: string): string =
  ## Hash password using libsodium `crypto_pwhash_str`
  ## using the recommended algorithm. The output is ASCII-only
  ## and database-safe.
  crypto_pwhash_str(password)

proc password_needs_rehashing*(password: string): bool =
  crypto_pwhash_str_needs_rehash(password) != 0


# # Cookies and session

proc set_auth_cookie*(self: HTTPAuth, value: string) =
  ## Set auth session cookie
  ## FIXME dot on domain
  let cookie = setCookie(
    self.cookie_name, value, domain=self.domain, path="",
    secure=self.https_only_cookies, httpOnly=true
  )
  assert cookie.startswith("Set-Cookie: ")
  self.headers.add("Set-Cookie", cookie[12..^1])


proc delete_auth_cookie*(self: HTTPAuth) =
  ## Delete auth session cookie
  ## FIXME dot on domain
  let cookie = setCookie(
    self.cookie_name, "", expires=deleted_cookie_expiration_time,
    domain=self.domain, path="",
    secure=self.https_only_cookies, httpOnly=true
  )
  assert cookie.startswith("Set-Cookie: ")
  self.headers.add("Set-Cookie", cookie[12..^1])

proc store_session(self: HTTPAuth, username: string) =
  ## Set or update session
  let
    session_desc = "session|$#" % username
    ciphertext = crypto_secretbox_easy(self.session_key, session_desc)
    encoded = safe_encode(ciphertext)
  self.set_auth_cookie(encoded)

proc get_auth_cookie(self: HTTPAuth, headers: HttpHeaders): string =
  ## Extract auth session cookie from HttpHeaders
  let chdr = headers.getOrDefault("Cookie")
  if chdr == "":
    return ""
  let cookies = parseCookies(chdr)
  if not cookies.hasKey(self.cookie_name):
    return ""
  return cookies[self.cookie_name]

proc get_session(self: HTTPAuth): string =
  ## Get current session from a cookie
  assert self.headers != nil
  let cookie_cyphertext = self.get_auth_cookie(self.headers)
  if cookie_cyphertext == "": return ""
  let decoded = safe_decode(cookie_cyphertext)
  try:
    let session_desc = crypto_secretbox_open_easy(self.session_key, decoded)
    if session_desc.startswith("session|"):
      return session_desc[8..^1]
    debug "Unable to parse session cookie"
    return ""
  except ValueError:
    debug "Unable to decrypt cookie"
    return ""


# # Misc

proc get_current_user_level*(self: HTTPAuth): int =
  ## Get level for an user
  let user = self.current_user
  return self.backend.get_role(user.role).level

proc is_user_anonymous*(self: HTTPAuth): bool =
  ## Check if the current user is anonymous
  assert self.headers != nil
  let username = self.get_session()
  if username == "":
    return true
  discard self.backend.get_user(username)
  return false


# # Procs that can be run by unauthenticated users

proc verify_password(password, pwhash: string): bool =
  ## Verify password hashed by libsodium
  return crypto_pwhash_str_verify(pwhash, password)

proc login*(self: HTTPAuth, username, password: string) =
  ## Check login credentials and set a cookie on success
  ## Do not leak out if a login is failed due to incorrect password
  ## or inexistent user to prevent user enumeration.
  var user: User
  try:
    user = self.backend.get_user(username)
  except UserNotFoundError:
    raise newException(LoginError, "Failed login")
  # FIXME prevent timing attacks

  assert user.hash != ""
  let authenticated = verify_password(password, user.hash)
  if not authenticated:
    raise newException(LoginError, "Failed login")

  if password_needs_rehashing(user.hash):
    user.hash = password_pwhash_str(password)
    self.backend.set_user(user)

  self.store_session(username)

  # if login_time
  # user.last_login = getEpoch().utcnow()
  # self.backend.set_user(User)

proc logout*(self: HTTPAuth) =
  ## Logout by removing the cookie
  if self.is_user_anonymous() == true:
    return
  self.delete_auth_cookie()

proc generate_registration_code(): string =
  ## Generate random registration code
  safe_encode(randombytes(64))

proc register*(self: HTTPAuth, username, password, email_addr: string, role="user",
              max_level=50, subject="Signup confirmation",
              email_template="registration_email.tpl",
              description="") =
  ## Register a new user account. An email with a registration validation is sent to the user
  ## The default role is "user".
  ## Attept to create users having role with level > max_level will throw LevelError
  ## Warning: this method is available to unauthenticated users
  assert username != "", "Username must be provided."
  assert password != "", "A password must be provided."
  assert email_addr != "", "An email address must be provided."
  try:
    discard self.backend.get_user(username)
    raise newException(UserExistsError, "User is already existing.")
  except:
    discard

  var role_o: Role
  try:
    role_o = self.backend.get_role(role)
  except:
    raise newException(RoleExistsError, "Role is not existing.")
  if role_o.level > max_level:
    raise newException(LevelError, "Unauthorized role.")

  let
    registration_code = generate_registration_code()
    creation_date = getTime().utc()

    registration_email_fn = "registration_email.tpl"
    registration_email_tpl = registration_email_fn.readFile

  let
    url = "APP_URL"  # FIXME
    email_text = registration_email_tpl.format(
      username,
      url,
      registration_code,
      email_addr,
      role,
      creation_date
    )

  # send registration email
  asyncCheck self.mailer.send_email(email_addr, subject, email_text)

  # store pending registration
  let pwhash = password_pwhash_str(password)

  self.backend.set_pending_registration(registration_code, PendingRegistration(
    username: username,
    role: role,
    hash: pwhash,
    email_addr: email_addr,
    description: description,
    creation_date: creation_date,
  ))
  self.backend.save_pending_registrations()

type ResetContainer = tuple[username, email_addr, tstamp: string]

proc validate_registration*(self: HTTPAuth, registration_code: string) =
  ## Validate pending account registration; create a new account if successful.
  var r: PendingRegistration
  try:
    r = self.backend.get_pending_registration(registration_code)
  except PendingRegistrationNotFoundError:
    raise newException(AuthError, "Invalid registration")

  try:
    discard self.backend.get_user(r.username)
    self.backend.delete_pending_registration(registration_code)
    raise newException(UserExistsError, "User is already existing.")
  except:
    discard

  var role_o: Role
  try:
    role_o = self.backend.get_role(r.role)
  except UserNotFoundError:
    raise newException(AuthError, "Nonexistent user role.")

  # the user data is moved from pending_registrations to _users
  let tstamp = getTime().utc
  self.backend.set_user(User(
      username: r.username,
      role: r.role,
      hash: r.hash,
      email_addr: r.email_addr,
      description: r.description,
      creation_date: r.creation_date,
      last_login: tstamp, # TODO should be nil?
    ))
  self.backend.save_users()


proc generate_reset_code(self: HTTPAuth, username, email_addr: string): string =
  ## Generate a reset_code token
  assert username != ""
  assert email_addr != ""
  let
    tstamp = getTime()
    msg = "reset|$#|$#|$#" % [username, email_addr, $tstamp]
    ciphertext = crypto_secretbox_easy(self.session_key, msg)
  ciphertext.safe_encode()

proc send_password_reset_email*(self: HTTPAuth, username="", email_addr="",
        subject="Password reset confirmation",
        email_template="views/password_reset_email") =
  ## Email the user with a link to reset his/her password
  ## If only username or email_addr is passed, fetch the other from the users
  ## database. If both are passed they will be matched against the users
  ## database as a security check.

  if username == "" and email_addr == "":
    raise newException(AuthError, "At least `username` or `email_addr` must be specified.")

  let user =
    if username == "":
      self.backend.get_user_by_email(email_addr)
    else:
      self.backend.get_user(username)

  # if both username and email_addr are provided crosscheck them
  if username != "" and email_addr != "" and user.email_addr != email_addr:
    raise newException(AuthError, "Username/email address pair not found.")

  # generate a reset_code token
  let reset_code = self.generate_reset_code(user.username, user.email_addr)

  # send reset email
  let registration_email_fn = "password_reset_email.tpl"
  let registration_email_tpl = registration_email_fn.readFile
  let email_text = registration_email_tpl.format(
    username,
    email_addr,
    reset_code,
    getTime().utc()
  )
  assert self.mailer.sender_email_addr != ""
  asyncCheck self.mailer.send_email(email_addr, subject, email_text)


proc validate_reset_code(self: HTTPAuth, reset_code: string): (string, string) =
  ## Decrypt and validate reset code
  ## Return username, email_addr, tstamp
  let decoded = reset_code.safe_decode()
  let reset_msg = crypto_secretbox_open_easy(self.session_key, decoded)
  if not reset_msg.startswith("reset|"):
    error "Unexpected reset code"
    raise newException(AuthError, "Unexpected reset code")

  let r = reset_msg.split('|')
  return (r[1], r[2])


proc reset_password*(self: HTTPAuth, reset_code, password: string) =
  ## Validate reset_code and update the account password
  ## The username is extracted from the reset_code token
  let (username, email_addr) = self.validate_reset_code(reset_code)
  var user = self.backend.get_user(username)
  if user.email_addr != email_addr:
    raise newException(AuthError, "Incorrect email address in reset code")
  user.hash = password_pwhash_str(password)
  self.backend.set_user(user)
  self.backend.save_users()



# # Procs that *should* be run only by users with the right access level

proc list_users*(self: HTTPAuth): seq[User] =
  ## List users
  return self.backend.list_users()

proc list_roles*(self: HTTPAuth): seq[Role] =
  ## List roles
  return self.backend.list_roles()

proc list_pending_registrations*(self: HTTPAuth): seq[PendingRegistration] =
  ## List pending registrations
  return self.backend.list_pending_registrations()

# # Procs that *can* be run only by users with the right access level

proc create_user*(self: HTTPAuth, username, password: string, role = "user",
    email_addr="", description="") =
  ## Create user. Warning: exposing this to unauthenticated users
  ## allow account creation without confirmation emails.
  assert username != "", "Username must be provided."
  if self.get_current_user_level < admin_level:
    raise newException(AuthError,
      "The current user is not authorized to create users.")

  try:
    discard self.backend.get_user(username)
    raise newException(UserExistsError, "User is already existing.")
  except:
    discard

  var role_o: Role
  try:
    role_o = self.backend.get_role(role)
  except:
    raise newException(AuthError, "Nonexistent user role.")

  let pwhash = password_pwhash_str(password)
  let tstamp = getTime().utc
  self.backend.set_user(User(
    username: username,
    role: role,
    hash: pwhash,
    email_addr: email_addr,
    description: description,
    creation_date: tstamp,
    last_login: tstamp
  ))
  self.backend.save_users()

proc delete_user*(self: HTTPAuth, username: string) =
  ## Delete user. This method is available to users with level>=100
  if self.get_current_user_level < admin_level:
    raise newException(AuthError,
      "The current user is not authorized to delete users.")

  try:
    discard self.backend.get_user(username)
  except:
    raise newException(UserExistsError, "User is not existing.")

  self.backend.delete_user(username)
  self.backend.save_users()


proc create_role*(self: HTTPAuth, role: string, level: int) =
  ## Create role. This method is available to users with level>=100
  assert role != "", "Role must be provided."
  if self.get_current_user_level < admin_level:
    echo self.get_current_user_level
    raise newException(AuthError,
      "The current user is not authorized to create roles.")

  try:
    discard self.backend.get_role(role)
    raise newException(RoleExistsError, "Role is already existing.")
  except:
    discard

  self.backend.set_role(Role(
    name: role,
    level: level
  ))
  self.backend.save_roles()

proc delete_role*(self: HTTPAuth, role: string) =
  ## Delete role. This method is available to users with level>=100
  assert role != "", "Role must be provided."
  ## TODO check for users with that role in a transaction
  if self.get_current_user_level < admin_level:
    raise newException(AuthError,
      "The current user is not authorized to delete roles.")

  try:
    discard self.backend.get_role(role)
  except:
    raise newException(RoleExistsError, "Role is not existing.")
  self.backend.delete_role(role)
  self.backend.save_roles()



# Internals

const one_day = 24 * 3600

proc newHTTPAuth*(domain: string, backend: HTTPAuthBackend, cookie_name="", cookie_domain="",
    password_reset_timeout=one_day, session_key="", https_only_cookies=true): HTTPAuth =
  ## Initialize HTTPAuth
  result = HTTPAuth(domain: domain, backend: backend,
    password_reset_timeout: password_reset_timeout,
    https_only_cookies: https_only_cookies,
  )
  result.mailer = newMailer() #FIXME: pass arguments
  assert result.backend != nil

  result.cookie_name = if cookie_name == "": domain else: cookie_name
  result.cookie_domain =
    if cookie_domain == "":
      "." & domain
    else: cookie_domain

  if session_key.len == 0:
    info "Generating volatile session key: if the HTTP service is restarted, all user session will be voided"
    result.session_key = randombytes(crypto_secretbox_KEYBYTES())
  elif session_key.len == crypto_secretbox_KEYBYTES():
    result.session_key = session_key
  else:
    raise newException(Exception, "session_key must be $# bytes long" % $crypto_secretbox_KEYBYTES())

proc shutdown*(self: HTTPAuth) =
  ## Terminate DB connections, close files
  self.backend.shutdown()

proc headers_hook*(self: var HTTPAuth, headers: HttpHeaders) =
  ## Capture headers sent by client
  self.headers = headers
  #assert self.headers != nil, "FIXME"

proc initialize_admin_user*(self: HTTPAuth, username="admin", password="", role="admin",
    email_addr="", description="Admin user") =
  ## Create initial admin user and role.
  ## The password can be given or autogenerated
  var password = password
  if password == "":
    password = safe_encode(randombytes(8))
    info "***********************************"
    info "Generating random admin password..."
    info "Generated password: '$#'" % password
    info "***********************************"

  self.backend.set_role(Role(
    name: role,
    level: admin_level
  ))
  self.backend.save_roles()
  let pwhash = password_pwhash_str(password)
  let tstamp = getTime().utc
  self.backend.set_user(User(
    username: username,
    role: role,
    hash: pwhash,
    email_addr: email_addr,
    description: description,
    creation_date: tstamp,
    last_login: tstamp
  ))

  self.backend.save_users()

# Cookies and session management

proc current_user*(self: HTTPAuth): User =
  ## Get current user or raise AuthError
  assert self.headers != nil
  let username = self.get_session()
  if username == "":
    raise newException(AuthError, "User is not logged in")
  self.backend.get_user(username)


proc require*(self: HTTPAuth, username="", role="", fixed_role=false) =
  ## Require the user to be authenticated. Optionally requires a fixed
  ## username, or a role with level greater or equal to the given role,
  ## or a fixed role.
  ## If no username or role is specified, any authenticated user will be
  ## authorized.
  let user = self.current_user()
  if username != "" and user.username != username:
    raise newException(AuthError, "Username not authorized")

  if role != "":
    let required_level = self.backend.get_role(role).level
    if fixed_role and user.role != role:
      raise newException(AuthError, "Incorrect role")
    else:
      let user_level = self.backend.get_role(user.role).level
      let required_level = self.backend.get_role(role).level
      if user_level < required_level:
        raise newException(AuthError, "Insufficient role")



proc update_user_password*(self: HTTPAuth, username, password: string) =
  ## Update user password
  var user = self.backend.get_user(username)
  user.hash = password_pwhash_str(password)
  self.backend.set_user(user)
  self.backend.save_users()

proc update_user_description*(self: HTTPAuth, username, description: string) =
  ## Update user description
  var user = self.backend.get_user(username)
  user.description = description
  self.backend.set_user(user)
  self.backend.save_users()

proc update_user_role*(self: HTTPAuth, username, role: string) =
  ## Update user role
  var user = self.backend.get_user(username)
  discard self.backend.get_role(role)
  user.role = role
  self.backend.set_user(user)
  self.backend.save_users()

proc update_user_email_address*(self: HTTPAuth, username, email_addr: string) =
  ## Update user email address
  var user = self.backend.get_user(username)
  user.email_addr = email_addr
  self.backend.set_user(user)
  self.backend.save_users()
