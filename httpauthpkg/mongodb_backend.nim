#
## Nim HTTP Authentication and Authorization - MongoDB backend
#
# Copyright 2017 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file

import logging,
  strutils,
  times,
  uri

from net import Port

import base

import
  nimongo.bson,
  nimongo.mongo


type
  MongoDbBackend = ref object of HTTPAuthBackend
    client: Mongo
    db_name: string
    user_collection, role_collection, pending_reg_collection: Collection[mongo.Mongo]


proc create_collections(self: MongoDbBackend) =
  ## Create collections
  let db = self.client[self.db_name]
  var status = db.createCollection("pending_registrations")
  if status.ok == false and status.err != "collection already exists":
    raise newException(Exception, status.err)
  status = db.createCollection("roles")

  if status.ok == false and status.err != "collection already exists":
    raise newException(Exception, status.err)
  status = db.createCollection("users")

  if status.ok == false and status.err != "collection already exists":
    raise newException(Exception, status.err)

proc newMongoDbBackend*(db_uri="mongodb://localhost/httpauth_test", ): MongoDbBackend =
  ## Initialize MongoDbBackend
  ## db_uri: see https://docs.mongodb.com/manual/reference/connection-string/
  doAssert db_uri.startswith("mongodb://")
  let uri: Uri = parseUri(db_uri)
  doAssert uri.path.startswith("/")

  var self = MongoDbBackend()
  self.db_name = uri.path[1..^1]
  self.client = newMongoWithURI(uri)

  if self.client.connect() == false:
    raise newException(Exception, "Unable to connect to MongoDB at '$#'" % db_uri)

  self.create_collections()
  self.user_collection = self.client[self.db_name]["users"]
  self.role_collection = self.client[self.db_name]["roles"]
  self.pending_reg_collection = self.client[self.db_name]["pending_registrations"]
  return self


# Date conversion

const timestamp_format = "yyyy-MM-dd HH:mm:ss"

proc db_to_timeinfo(d: string): TimeInfo =
  d.parseInt.fromSeconds.getGMTime()

proc timeinfo_to_db(t: TimeInfo): string =
  $t.toTime.toSeconds().int


# User

method get_user*(self: MongoDbBackend, username: string): User =
  ## Get User
  assert username != ""
  var u: Bson
  try:
    u = self.user_collection.find(%*{"name": username}).one()
  except mongo.NotFound:
    raise newException(UserNotFoundError, "User '$#' not found" % username)

  return User(
    username:u["name"],
    role:u["role"],
    description:u["description"],
    email_addr:u["email_addr"],
    hash:u["hash"],
    creation_date:u["creation_date"].db_to_timeinfo(),
    last_login:u["last_login"].db_to_timeinfo(),
  )

method get_user_by_email*(self: MongoDbBackend, email_addr: string): User =
  ## Get User by email address
  assert email_addr != ""
  var u: Bson
  try:
    u = self.user_collection.find(%*{"email_addr": email_addr}).one()
  except mongo.NotFound:
    raise newException(UserNotFoundError, "User with email address '$#' not found" % email_addr)

  return User(
    username:u["name"],
    role:u["role"],
    description:u["description"],
    email_addr:u["email_addr"],
    hash:u["hash"],
    creation_date:u["creation_date"].db_to_timeinfo(),
    last_login:u["last_login"].db_to_timeinfo(),
  )

method set_user*(self: MongoDbBackend, user: User) =
  ## Set User
  assert user.username != ""
  let i = %* {
    "name": user.username,
    "role": user.role,
    "description": user.description,
    "email_addr": user.email_addr,
    "hash": user.hash,
    "creation_date": user.creation_date.timeinfo_to_db(),
    "last_login": user.last_login.timeinfo_to_db()
  }
  # upsert
  let reply = self.user_collection.update(%*{"name": user.username}, i, false, true)
  if reply.ok == false:
    raise newException(Exception, reply.err)

method delete_user*(self: MongoDbBackend, username: string) =
  ## Delete User
  self.user_collection.remove(%*{"name": username})

method count_users*(self: MongoDbBackend): int =
  ## Count users
  self.user_collection.count()

method list_users*(self: MongoDbBackend): seq[User] =
  ## List users
  result = @[]
  try:
    for u in self.user_collection.find(%*{}):
      result.add User(
        username:u["name"],
        role:u["role"],
        description:u["description"],
        email_addr:u["email_addr"],
        hash:u["hash"],
        creation_date:u["creation_date"].db_to_timeinfo(),
        last_login:u["last_login"].db_to_timeinfo(),
      )
  except Exception:
    raise getCurrentException()

# Role

method get_role*(self: MongoDbBackend, role: string): Role =
  ## Get Role
  assert role != ""
  let r = self.role_collection.find(%*{"name": role}).one()
  return Role(name: role, level: r["level"])

method set_role*(self: MongoDbBackend, role: Role) =
  ## Set Role
  let reply = self.role_collection.update(
    %*{"name": role.name},
    %*{"name": role.name, "level": role.level},
    false,
    true
  )

method create_role*(self: MongoDbBackend, role: Role) =
  ## Set Role
  self.role_collection.insert(%*{"name": role.name, "level": role.level})

method update_role*(self: MongoDbBackend, role: Role) =
  ## Update existing role
  let reply = self.role_collection.update(
    %*{"name": role.name},
    %*{"level": role.level},
    false,
    false,
  )
  ## FIXME

method delete_role*(self: MongoDbBackend, role: string) =
  ## Delete Role
  try:
    self.role_collection.remove(%*{"name": role})
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      raise newException(RoleNotFoundError, "Role '$#' not found" % role)
    else:
      raise getCurrentException()

method count_roles*(self: MongoDbBackend): int =
  ## Count roles
  self.role_collection.count()

method list_roles*(self: MongoDbBackend): seq[Role] =
  ## List roles
  result = @[]
  try:
    for r in self.role_collection.find(%*{}):
      result.add Role(name: r["name"], level: r["level"])
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      return
    raise getCurrentException()


# PendingRegistration

method get_pending_registration*(self: MongoDbBackend, reg_code: string): PendingRegistration =
  ## Get PendingRegistration
  assert reg_code != ""
  var r: Bson
  try:
    r = self.pending_reg_collection.find(%*{"code": reg_code}).one()
  except mongo.NotFound:
    raise newException(PendingRegistrationNotFoundError, "Pending registration with code '$#' not found" % reg_code)

  return PendingRegistration(
    creation_date: r["creation_date"].db_to_timeinfo(),
    description: r["description"],
    email_addr: r["email_addr"],
    hash: r["hash"],
    role: r["role"],
    username: r["name"],
  )

method set_pending_registration*(self: MongoDbBackend, reg_code: string, pending_registration: PendingRegistration) =
  ## Insert PendingRegistration
  let r = %* {
    "code": reg_code,
    "creation_date": pending_registration.creation_date.timeinfo_to_db(),
    "description": pending_registration.description,
    "email_addr": pending_registration.email_addr,
    "hash": pending_registration.hash,
    "name": pending_registration.username,
    "role": pending_registration.role,
  }
  self.pending_reg_collection.insert(r)

method delete_pending_registration*(self: MongoDbBackend, reg_code: string) =
  ## Delete PendingRegistration
  self.pending_reg_collection.remove(%*{"code": reg_code})

method count_pending_registrations*(self: MongoDbBackend): int =
  ## Count pending_registrations
  self.pending_reg_collection.count()

method list_pending_registrations*(self: MongoDbBackend): seq[PendingRegistration] =
  ## List pending_registrations
  result = @[]
  try:
    for r in self.pending_reg_collection.find(%*{}):
      result.add PendingRegistration(
        creation_date: r["creation_date"].db_to_timeinfo(),
        description: r["description"],
        email_addr: r["email_addr"],
        hash: r["hash"],
        role: r["role"],
        username: r["name"],
      )
  except Exception:
    if getCurrentExceptionMsg() == "404 Not Found - Key not found":
      return
    raise getCurrentException()

method purge_all_tables*(self: MongoDbBackend) =
  ## Drop collections
  var resp = self.pending_reg_collection.drop()
  if resp.ok == false:
    echo "pending_reg ", resp.message
  resp = self.user_collection.drop()
  if resp.ok == false:
    echo "users ", resp.message
  resp = self.role_collection.drop()
  if resp.ok == false:
    echo "roles ", resp.message
  self.create_collections()

