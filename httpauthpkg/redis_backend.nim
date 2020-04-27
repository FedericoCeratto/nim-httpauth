#
## Nim HTTP Authentication and Authorization - redis backend
#
# Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file

import logging,
  pegs,
  redis,
  strutils,
  times

import os #fixme /
from net import Port

import base

type
  RedisBackend = ref object of HTTPAuthBackend
    client: Redis
    basepath, userpath, rolepath, pending_reg_path: string



let db_uri_peg = peg"""
uri <- dbtype '://' userpass hostname port '/' schema
dbtype <- {'redis'}

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
    assert matches[0] == "redis"
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


proc newRedisBackend*(db_uri="httpauth.sqlite3"): RedisBackend =
  ## Initialize RedisBackend
  ## <engine>://[<dbuser>[:[<dbpassword>]]@]<host>[:port]/<schema>
  ## redis://localhost/httpauth_test
  let uri = parse_uri(db_uri)
  assert uri.schema != ""

  var self = RedisBackend()
  self.client = open(
    host="127.0.0.1", port=6379.Port
  )

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


# User

import tables
from sequtils import distribute

proc toTable(li: RedisList): Table[string, string] =
  let n = li.len div 2
  result = initTable[string, string](rightSize(n))
  for item in li.distribute(n):
    result[item[0]] = item[1]

method get_user*(self: RedisBackend, username: string): User =
  ## Get User
  assert username != ""
  let item = self.client.hGetAll(self.userpath / username)
  if item.len == 0:
    raise newException(UserNotFoundError, "User '$#' not found" % username)

  let u = item.toTable()
  return User(
    username:username,
    role:u["role"],
    description:u["description"],
    email_addr:u["email_addr"],
    hash:u["hash"],
    creation_date:u["creation_date"].db_to_datetime(),
    last_login:u["last_login"].db_to_datetime(),
  )

method get_user_by_email*(self: RedisBackend, email_addr: string): User =
  ## Get User by email address
  ## Warning: very slow execution - it scans through all the users
  assert email_addr != ""
  for key in self.client.keys(self.userpath / "*"):
    let item = self.client.hGetAll(key)
    if item.len == 0:
      continue  # The item has been deleted during before fetching it
    let u = item.toTable()
    if u["email_addr"] == email_addr:
      let username = key[(self.userpath.len + 1)..^0]
      return User(
        username:username,
        role:u["role"],
        description:u["description"],
        email_addr:u["email_addr"],
        hash:u["hash"],
        creation_date:u["creation_date"].db_to_datetime(),
        last_login:u["last_login"].db_to_datetime(),
      )
  raise newException(UserNotFoundError, "User with email address '$#' not found" % email_addr)

method set_user*(self: RedisBackend, user: User) =
  ## Set User
  assert user.username != ""
  self.client.hMSet(self.userpath / user.username,
    @[
      ("role", user.role),
      ("description", user.description),
      ("email_addr", user.email_addr),
      ("hash", user.hash),
      ("creation_date", user.creation_date.datetime_to_db()),
      ("last_login", user.last_login.datetime_to_db())
    ]
  )

method delete_user*(self: RedisBackend, username: string) =
  ## Delete User
  discard self.client.del(@[self.userpath / username])

method count_users*(self: RedisBackend): int =
  ## Count users
  self.client.keys(self.userpath / "*").len

method list_users*(self: RedisBackend): seq[User] =
  ## List users
  result = @[]
  for key in self.client.keys(self.userpath / "*"):
    let username = key[(self.userpath.len + 1)..^0]
    let item = self.client.hGetAll(key)
    if item.len == 0:
      raise newException(UserNotFoundError, "User '$#' not found" % username)
    let u = item.toTable()
    result.add User(
      username:username,
      role:u["role"],
      description:u["description"],
      email_addr:u["email_addr"],
      hash:u["hash"],
      creation_date:u["creation_date"].db_to_datetime(),
      last_login:u["last_login"].db_to_datetime(),
    )


# Role

method get_role*(self: RedisBackend, role: string): Role =
  ## Get Role
  assert role != ""
  let r = self.client.get(self.rolepath / role)
  return Role(name: role, level: r.parseInt)

method set_role*(self: RedisBackend, role: Role) =
  ## Set Role
  self.client.setk(self.rolepath / role.name, $role.level)

method create_role*(self: RedisBackend, role: Role) =
  ## Set Role
  self.client.setk(self.rolepath / role.name, $role.level)

method update_role*(self: RedisBackend, role: Role) =
  ## Set Role
  self.client.setk(self.rolepath / role.name, $role.level)

method delete_role*(self: RedisBackend, role: string) =
  ## Delete Role
  discard self.client.del(@[self.rolepath / role])

method count_roles*(self: RedisBackend): int =
  ## Count roles
  self.client.keys(self.rolepath / "*").len

method list_roles*(self: RedisBackend): seq[Role] =
  ## List roles
  result = @[]
  for key in self.client.keys(self.rolepath / "*"):
    let item = self.client.get(key)
    if item == "" or item.len == 0:
      continue
    let rolename = key[(self.rolepath.len + 1)..^0]
    result.add Role(
      name: rolename,
      level: item.parseInt
    )

# PendingRegistration

method get_pending_registration*(self: RedisBackend, reg_code: string): PendingRegistration =
  ## Get PendingRegistration
  assert reg_code != ""
  let item = self.client.hGetAll(self.pending_reg_path / reg_code)
  if item.len == 0:
    raise newException(PendingRegistrationNotFoundError, "Pending registration with code '$#' not found" % reg_code)

  let r = item.toTable()
  return PendingRegistration(
    creation_date: r["creation_date"].db_to_datetime(),
    description: r["description"],
    email_addr: r["email_addr"],
    hash: r["hash"],
    role: r["role"],
    username: r["name"],
  )

method set_pending_registration*(self: RedisBackend, reg_code: string, pending_registration: PendingRegistration) =
  ## Set PendingRegistration
  self.client.hMSet(self.pending_reg_path / reg_code,
    @[
      ("creation_date", pending_registration.creation_date.datetime_to_db()),
      ("description", pending_registration.description),
      ("email_addr", pending_registration.email_addr),
      ("hash", pending_registration.hash),
      ("name", pending_registration.username),
      ("role", pending_registration.role),
    ]
  )

method delete_pending_registration*(self: RedisBackend, reg_code: string) =
  ## Delete PendingRegistration
  discard self.client.del(@[self.pending_reg_path / reg_code])

method count_pending_registrations*(self: RedisBackend): int =
  ## Count pending_registrations
  self.client.keys(self.pending_reg_path / "*").len

method list_pending_registrations*(self: RedisBackend): seq[PendingRegistration] =
  ## List pending_registrations
  result = @[]
  for key in self.client.keys(self.pending_reg_path / "*"):
    let username = key[(self.pending_reg_path.len + 1)..^0]
    let item = self.client.hGetAll(key)
    #if item == nil or item.len == 0:
    #FIXME no reg_code in PendingRegistration
    let r = item.toTable()
    result.add PendingRegistration(
      creation_date: r["creation_date"].db_to_datetime(),
      description: r["description"],
      email_addr: r["email_addr"],
      hash: r["hash"],
      role: r["role"],
      username: r["name"],
    )


method purge_all_tables*(self: RedisBackend) =
  for key in self.client.keys(self.basepath / "*"):
    discard self.client.del(@[key])
