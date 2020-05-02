#
## Nim HTTP Authentication and Authorization - etcd backend
#
# Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file

import logging,
  strutils,
  pegs,
  times

import base

import etcd_client


type
  EtcdBackend = ref object of HTTPAuthBackend
    client: EtcdClient
    basepath, userpath, rolepath, pending_reg_path: string



let db_uri_peg = peg"""
uri <- dbtype '://' userpass hostname port '/' schema
dbtype <- {'etcd'}

userpass <- bothuserpass / onlyuser / nousernopass
bothuserpass <- ({\w+} ':' {\w+} '@')
onlyuser <- ({\w+} {\\?} '@')
nousernopass <- ( {\\?} {\\?} )

hostname <- {\w+(\.\w+)*}
port <- (':' {\d+}) / ({\\?})
schema <- {\w+}
"""


type DBURI* = object of RootObj
  engine*, user*, password*, hostname*, schema*: string
  #port*: Port

proc parse_uri*(uri: string): DBURI =
  ## Parse DB URI
  if uri =~ db_uri_peg:
    assert matches[0] == "etcd"
    let port =
      try:
        matches[4].parseInt()
      except:
        2379

    return DBURI(
      engine:matches[0],
      user:matches[1],
      password:matches[2],
      hostname:matches[3],
      #port:port,
      schema:matches[5]
    )

  raise newException(Exception, "Unable to parse DB URI $#" % uri)


proc newEtcdBackend*(db_uri="httpauth.sqlite3"): EtcdBackend =
  ## Initialize EtcdBackend
  ## <engine>://[<dbuser>[:[<dbpassword>]]@]<host>[:port]/<schema>
  ## etcd://localhost/httpauth_test
  let uri = parse_uri(db_uri)
  assert uri.schema != ""

  var self = EtcdBackend()
    #hostname=uri.hostname, port=2379, proto="http", srv_domain="",
  self.client = new_etcd_client(
    hostname="127.0.0.1", port=2379, proto="http", srv_domain="",
    read_timeout=60, failover=true, cert="", ca_cert="", username="",
    password="", reconnect=true)

  self.basepath = uri.schema
  self.userpath = uri.schema / "users"
  self.rolepath = uri.schema / "roles"
  self.pending_reg_path = uri.schema / "pending_reg"
  return self


# Date conversion

const timestamp_format = "yyyy-MM-dd HH:mm:ss"

proc db_to_datetime(d: string): DateTime =
  d.parseInt.fromUnix.utc()

proc datetime_to_db(t: DateTime): string =
  $t.toTime.toUnixFloat().int

import json

# User

method get_user*(self: EtcdBackend, username: string): User =
  ## Get User
  assert username != ""
  var u: JsonNode
  try:
    let item = self.client.get(self.userpath / username)
    u = item["value"].str.parseJson
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      raise newException(UserNotFoundError, "User '$#' not found" % username)
    raise getCurrentException()

  return User(
    username:username,
    role:u["role"].str,
    description:u["description"].str,
    email_addr:u["email_addr"].str,
    hash:u["hash"].str,
    creation_date:u["creation_date"].str.db_to_datetime(),
    last_login:u["last_login"].str.db_to_datetime(),
  )

method get_user_by_email*(self: EtcdBackend, email_addr: string): User =
  ## Get User by email address
  ## Warning: very slow execution - it scans through all the users
  assert email_addr != ""
  var users_jarray: JsonNode
  try:
    users_jarray = self.client.ls(self.userpath)["nodes"]
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      raise newException(UserNotFoundError, "User with email address '$#' not found" % email_addr)
    raise

  for item in users_jarray:
    let u = item["value"].str.parseJson
    if u["email_addr"].str == email_addr:
      let username = item["key"].str.rsplit({'/'}, maxsplit=1)[1]
      return User(
        username:username,
        role:u["role"].str,
        description:u["description"].str,
        email_addr:u["email_addr"].str,
        hash:u["hash"].str,
        creation_date:u["creation_date"].str.db_to_datetime(),
        last_login:u["last_login"].str.db_to_datetime(),
      )

  raise newException(UserNotFoundError, "User with email address '$#' not found" % email_addr)

method set_user*(self: EtcdBackend, user: User) =
  ## Set User
  assert user.username != ""
  let i = %* {
    "role": user.role,
    "description": user.description,
    "email_addr": user.email_addr,
    "hash": user.hash,
    "creation_date": user.creation_date.datetime_to_db(),
    "last_login": user.last_login.datetime_to_db()
  }
  try:
    discard self.client.get(self.userpath / user.username)
    self.client.update(self.userpath / user.username, $i)
  except:
    self.client.create(self.userpath / user.username, $i)

method delete_user*(self: EtcdBackend, username: string) =
  ## Delete User
  self.client.del(self.userpath / username)

method count_users*(self: EtcdBackend): int =
  ## Count users
  try:
    return self.client.ls(self.userpath)["nodes"].len
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      return 0
    raise getCurrentException()

method list_users*(self: EtcdBackend): seq[User] =
  ## List users
  result = @[]
  try:
    for item in self.client.ls(self.userpath)["nodes"]:
      let username = item["key"].str.rsplit({'/'}, maxsplit=1)[1]
      let u = item["value"].str.parseJson
      result.add User(
        username:username,
        role:u["role"].str,
        description:u["description"].str,
        email_addr:u["email_addr"].str,
        hash:u["hash"].str,
        creation_date:u["creation_date"].str.db_to_datetime(),
        last_login:u["last_login"].str.db_to_datetime(),
      )
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      return
    raise getCurrentException()

# Role

method get_role*(self: EtcdBackend, role: string): Role =
  ## Get Role
  assert role != ""
  let r = self.client.get(self.rolepath / role)
  return Role(name: role, level: r["value"].str.parseInt)

method set_role*(self: EtcdBackend, role: Role) =
  ## Set Role
  try:
    discard self.get_role(role.name)
    self.client.update(self.rolepath / role.name, $role.level)
  except Exception:
    self.client.create(self.rolepath / role.name, $role.level)

method create_role*(self: EtcdBackend, role: Role) =
  ## Set Role
  self.client.create(self.rolepath / role.name, $role.level)

method update_role*(self: EtcdBackend, role: Role) =
  ## Set Role
  self.client.update(self.rolepath / role.name, $role.level)

method delete_role*(self: EtcdBackend, role: string) =
  ## Delete Role
  try:
    self.client.del(self.rolepath / role)
    discard  # workaround for "Error: expression has no type:" error
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      raise newException(RoleNotFoundError, "Role '$#' not found" % role)
    raise getCurrentException()

method count_roles*(self: EtcdBackend): int =
  ## Count roles
  try:
    return self.client.ls(self.rolepath)["nodes"].len
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      return 0
    raise getCurrentException()

method list_roles*(self: EtcdBackend): seq[Role] =
  ## List roles
  result = @[]
  try:
    for item in self.client.ls(self.rolepath)["nodes"]:
      let rolename = item["key"].str.rsplit({'/'}, maxsplit=1)[1]
      result.add Role(
        name: rolename,
        level: item["value"].str.parseInt
      )
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      return
    raise getCurrentException()


# PendingRegistration

method get_pending_registration*(self: EtcdBackend, reg_code: string): PendingRegistration =
  ## Get PendingRegistration
  assert reg_code != ""
  var r: JsonNode
  try:
    let item = self.client.get(self.pending_reg_path / reg_code)
    r = item["value"].str.parseJson
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      raise newException(PendingRegistrationNotFoundError, "Pending registration with code '$#' not found" % reg_code)
    raise getCurrentException()

  let cdate = r["creation_date"].getInt().fromUnix().utc()
  return PendingRegistration(
    creation_date: cdate,
    description: r["description"].str,
    email_addr: r["email_addr"].str,
    hash: r["hash"].str,
    role: r["role"].str,
    username: r["name"].str,
  )

method set_pending_registration*(self: EtcdBackend, reg_code: string, pending_registration: PendingRegistration) =
  ## Set PendingRegistration
  let i = %* {
    "creation_date": pending_registration.creation_date.datetime_to_db(),
    "description": pending_registration.description,
    "email_addr": pending_registration.email_addr,
    "hash": pending_registration.hash,
    "name": pending_registration.username,
    "role": pending_registration.role,
  }
  self.client.create(self.pending_reg_path / reg_code, $i)

method delete_pending_registration*(self: EtcdBackend, reg_code: string) =
  ## Delete PendingRegistration
  self.client.del(self.pending_reg_path / reg_code)

method count_pending_registrations*(self: EtcdBackend): int =
  ## Count pending_registrations
  try:
    return self.client.ls(self.pending_reg_path)["nodes"].len
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      return 0
    raise getCurrentException()

method list_pending_registrations*(self: EtcdBackend): seq[PendingRegistration] =
  ## List pending_registrations
  result = @[]
  try:
    for item in self.client.ls(self.pending_reg_path)["nodes"]:
      #let username = item["key"].str.rsplit({'/'}, maxsplit=1)[1]
      #FIXME no reg_code in PendingRegistration
      let r = item["value"].str.parseJson
      let cdate = r["creation_date"].getInt().fromUnix().utc()
      result.add PendingRegistration(
        creation_date: cdate,
        description: r["description"].str,
        email_addr: r["email_addr"].str,
        hash: r["hash"].str,
        role: r["role"].str,
        username: r["name"].str,
      )
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      return
    raise getCurrentException()



method purge_all_tables*(self: EtcdBackend) =
  ## Recreate empty directories
  try:
    self.client.rmdir(self.basepath, recursive=true)
  except Exception:
    if getCurrentExceptionMsg() != "404 Not Found - Key not found":
      raise getCurrentException()
