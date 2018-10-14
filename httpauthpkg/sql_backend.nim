#
## Nim HTTP Authentication and Authorization - SQL Backend
#
# Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file

## The backend is designed for single-host web applications
## with infrequent changes to the authentication datastore.

import db_mysql,
  db_postgres,
  db_sqlite,
  logging,
  pegs,
  strutils,
  times

import base

type DBURI* = object of RootObj
  engine*, user*, password*, hostname*, schema*: string
  #port*: Port

type
  DBKind {.pure.} = enum mysql, postgres, sqlite

  SQLBackend = ref object of HTTPAuthBackend
    case db_kind: DBKind
    of DBKind.sqlite:   db_conn_sqlite:   db_sqlite.DbConn
    of DBKind.mysql:    db_conn_mysql:    db_mysql.DbConn
    of DBKind.postgres: db_conn_postgres: db_postgres.DbConn

proc open_db_connection(self: SQLBackend, uri: DBURI) =
  ## Setup DB connection
  case self.db_kind
  of DBKind.sqlite:
    self.db_conn_sqlite = db_sqlite.open(uri.hostname, uri.user, uri.password, uri.schema)
  of DBKind.mysql:
    self.db_conn_mysql = db_mysql.open(uri.hostname, uri.user, uri.password, uri.schema)
  of DBKind.postgres:
    self.db_conn_postgres = db_postgres.open(uri.hostname, uri.user, uri.password, uri.schema)

method shutdown*(self: SQLBackend) =
  ## Close db
  case self.db_kind
  of DBKind.sqlite: self.db_conn_sqlite.close()
  of DBKind.mysql: self.db_conn_mysql.close()
  of DBKind.postgres: self.db_conn_postgres.close()

proc db_exec*(self: SQLBackend, query: SqlQuery, a: varargs[string]): string {.discardable.} =
  ## Call exec(), abstact database type
  case self.db_kind
  of DBKind.sqlite: self.db_conn_sqlite.exec(query, a)
  of DBKind.mysql: self.db_conn_mysql.exec(query, a)
  of DBKind.postgres: self.db_conn_postgres.exec(query, a)

proc db_getrow(self: SQLBackend, query: SqlQuery, a: varargs[string]): seq[string] =
  ## Call getRow(), abstact database type
  case self.db_kind
  of DBKind.sqlite: self.db_conn_sqlite.getRow(query, a)
  of DBKind.mysql: self.db_conn_mysql.getRow(query, a)
  of DBKind.postgres: self.db_conn_postgres.getRow(query, a)

proc db_get_value(self: SQLBackend, query: SqlQuery, a: varargs[string]): string =
  ## Call getValue(), abstact database type
  case self.db_kind
  of DBKind.sqlite: self.db_conn_sqlite.getValue(query, a)
  of DBKind.mysql: self.db_conn_mysql.getValue(query, a)
  of DBKind.postgres: self.db_conn_postgres.getValue(query, a)

iterator db_get_rows(self: SQLBackend, query: SqlQuery, a: varargs[string]): seq[string] =
  case self.db_kind
  of DBKind.sqlite:
    for r in self.db_conn_sqlite.rows(query, a):
      yield r
  of DBKind.mysql:
    for r in self.db_conn_mysql.rows(query, a):
      yield r
  of DBKind.postgres:
    for r in self.db_conn_postgres.rows(query, a):
      yield r

method create_tables(self: SQLBackend) {.base.} =
  ## Create tables if needed
  self.db_exec(sql("""
    CREATE TABLE IF NOT EXISTS user (
      name varchar(64) not null UNIQUE,
      role varchar(64) not null,
      description varchar(1024),
      email_addr varchar(1024),
      hash varchar(1024) not null,
      creation_date TIMESTAMP,
      last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  """))
  self.db_exec(sql("""
    CREATE TABLE IF NOT EXISTS role (
      name varchar(50) not null PRIMARY KEY,
      level INTEGER
    )
  """))
  self.db_exec(sql("""
    CREATE TABLE IF NOT EXISTS pending_registration (
      reg_code varchar(1024) PRIMARY KEY,
      username varchar(64) not null,
      role varchar(64) not null,
      description varchar(64),
      email_addr varchar(64),
      hash varchar(1024) not null,
      creation_date TIMESTAMP
    );
  """))

let db_uri_peg = peg"""
uri <- dbtype '://' userpass hostname port '/' schema
dbtype <- {'mysql'/'sqlite'/'postgres'}

userpass <- bothuserpass / onlyuser / nousernopass
bothuserpass <- ({\w+} ':' {\w+} '@')
onlyuser <- ({\w+} {\\?} '@')
nousernopass <- ( {\\?} {\\?} )

hostname <- {\w+(\.\w+)*}
port <- (':' {\d+}) / ({\\?})
schema <- {\w+}
"""


proc parse_uri*(uri: string): DBURI =
  ## Parse DB URI
  if uri.startswith("sqlite://"):
    return DBURI(engine:"sqlite", user:"", password:"", hostname:uri[9..^1],
      schema:"")

  if uri =~ db_uri_peg:
    let port =
      try:
        matches[4].parseInt()
      except:
        case matches[0]
        of "mysql": 3306
        of "postgres": 5432
        else: 0

    return DBURI(
      engine:matches[0],
      user:matches[1],
      password:matches[2],
      hostname:matches[3],
      #port:port,
      schema:matches[5]
    )

  raise newException(Exception, "Unable to parse DB URI $#" % uri)




proc newSQLBackend*(db_uri="httpauth.sqlite3"): SQLBackend =
  ## Initialize SQLBackend
  ## <engine>://[<dbuser>[:[<dbpassword>]]@]<host>[:port]/<schema>
  ## postgresql://scott:tiger@localhost:5432/mydatabase
  ## mysql://localhost/httpauth_test
  let uri = parse_uri(db_uri)

  doAssert uri.engine in ["sqlite", "mysql", "postgres"]
  var self =
    if uri.engine == "sqlite":  SQLBackend(db_kind: DBKind.sqlite)
    elif uri.engine == "mysql": SQLBackend(db_kind: DBKind.mysql)
    else:                       SQLBackend(db_kind: DBKind.postgres)

  self.open_db_connection(uri)
  self.create_tables()
  return self





# Date conversion

const timestamp_format = "yyyy-MM-dd HH:mm:ss"

proc db_to_timeinfo(self: SQLBackend, d: string): DateTime =
  case self.db_kind
  of DBKind.sqlite:
    try:
      result = d.parseInt.fromUnix.utc()
    except Exception:
      error "Unable to parse timestamp '$#'" % d
      echo "Unable to parse timestamp '$#'" % d
      raise getCurrentException()

  of DBKind.mysql:
    result = d.parse(timestamp_format)
    #result.tzname = "UTC"  # tzname bug

  of DBKind.postgres:
    result = d.parse(timestamp_format)
    #result.tzname = "UTC"  # tzname bug

proc timeinfo_to_db(self: SQLBackend, t: DateTime): string =
  case self.db_kind
  of DBKind.sqlite:
    result = $t.toTime.toUnix()
  of DBKind.mysql:
    result = t.format(timestamp_format)
  of DBKind.postgres:
    result = t.format(timestamp_format)



# User

method get_user*(self: SQLBackend, username: string): User =
  ## Get User
  assert username != ""
  let u = self.db_getrow(sql"SELECT name,role,description,email_addr,hash,creation_date,last_login FROM user WHERE name=?", username)
  if u[0] == "":
    raise newException(UserNotFoundError, "User '$#' not found" % username)
  return User(
    username:u[0],
    role:u[1],
    description:u[2],
    email_addr:u[3],
    hash:u[4],
    creation_date:self.db_to_timeinfo(u[6]),
    last_login:self.db_to_timeinfo(u[6]),
  )

method get_user_by_email*(self: SQLBackend, email_addr: string): User =
  ## Get User by email address
  assert email_addr != ""
  let u = self.db_getrow(sql"SELECT name,role,description,email_addr,hash,creation_date,last_login FROM user WHERE email_addr=?", email_addr)
  if u[0] == "":
    raise newException(UserNotFoundError, "User with email address '$#' not found" % email_addr)
  return User(
    username:u[0],
    role:u[1],
    description:u[2],
    email_addr:u[3],
    hash:u[4],
    creation_date:self.db_to_timeinfo(u[6]),
    last_login:self.db_to_timeinfo(u[6]),
  )


method set_user*(self: SQLBackend, user: User) =
  ## Set User
  assert user.username != ""

  self.db_exec(sql"REPLACE INTO user (name,role,description,email_addr,hash,creation_date,last_login) VALUES (?,?,?,?,?,?,?)",
    user.username, user.role, user.description, user.email_addr, user.hash,
    self.timeinfo_to_db(user.creation_date),
    self.timeinfo_to_db(user.last_login)
  )

method delete_user*(self: SQLBackend, username: string) =
  ## Delete User
  self.db_exec(sql"DELETE FROM user WHERE name=?", username)

method count_users*(self: SQLBackend): int =
  ## Count users
  return self.db_get_value(sql"SELECT COUNT(name) FROM user").parseInt()

method list_users*(self: SQLBackend): seq[User] =
  ## List users
  result = @[]
  for u in self.db_get_rows(sql"SELECT * from user"):
    result.add User(
      username:u[0],
      role:u[1],
      description:u[2],
      email_addr:u[3],
      hash:u[4],
      creation_date:self.db_to_timeinfo(u[6]),
      last_login:self.db_to_timeinfo(u[6]),
    )

# Role

method get_role*(self: SQLBackend, role: string): Role =
  ## Get Role
  let r = self.db_getrow(sql"SELECT * FROM role WHERE name=?", role)
  if r[0] == "":
    raise newException(RoleNotFoundError, "Role '$#' not found" % role)
  return Role(name:r[0], level:r[1].parseInt)

method set_role*(self: SQLBackend, role: Role) =
  ## Set Role
  self.db_exec(sql"REPLACE INTO role (name,level) VALUES (?,?)",
    role.name, $role.level)

method delete_role*(self: SQLBackend, role: string) =
  ## Delete Role
  self.db_exec(sql"DELETE FROM role WHERE name=?", role)

method count_roles*(self: SQLBackend): int =
  ## Count roles
  return self.db_get_value(sql"SELECT COUNT(name) FROM role").parseInt()

method list_roles*(self: SQLBackend): seq[Role] =
  ## List roles
  result = @[]
  for r in self.db_get_rows(sql"SELECT * from role"):
    result.add Role(name:r[0], level:r[1].parseInt)

# PendingRegistration

method get_pending_registration*(self: SQLBackend, reg_code: string): PendingRegistration =
  ## Get PendingRegistration
  assert reg_code != ""
  let pr = self.db_getrow(sql"SELECT * FROM pending_registration WHERE reg_code=?", reg_code)
  if pr[0] == "":
    raise newException(PendingRegistrationNotFoundError,
      "Registration code '$#' not found" % reg_code)
  return PendingRegistration(
    username:pr[1],
    role:pr[2],
    description:pr[3],
    email_addr:pr[4],
    hash:pr[5],
    creation_date:self.db_to_timeinfo(pr[6]),
  )

method set_pending_registration*(self: SQLBackend, reg_code: string, pending_registration: PendingRegistration) =
  ## Set PendingRegistration

  self.db_exec(sql"REPLACE INTO pending_registration (reg_code,username,role,description,email_addr,hash,creation_date) VALUES (?,?,?,?,?,?,?)",
    reg_code,
    pending_registration.username,
    pending_registration.role,
    pending_registration.description,
    pending_registration.email_addr,
    pending_registration.hash,
    self.timeinfo_to_db(pending_registration.creation_date)
  )

method delete_pending_registration*(self: SQLBackend, reg_code: string) =
  ## Delete PendingRegistration
  self.db_exec(sql"DELETE FROM pending_registration WHERE reg_code=?", reg_code)

method count_pending_registrations*(self: SQLBackend): int =
  ## Count pending_registrations
  return self.db_get_value(sql"SELECT COUNT(reg_code) FROM pending_registration").parseInt()

method list_pending_registrations*(self: SQLBackend): seq[PendingRegistration] =
  ## List pending_registrations
  result = @[]
  for pr in self.db_get_rows(sql"SELECT * from pending_registration"):
    result.add PendingRegistration(
      username:pr[1],
      role:pr[2],
      description:pr[3],
      email_addr:pr[4],
      hash:pr[5],
      creation_date:self.db_to_timeinfo(pr[6])
    )

method purge_all_tables*(self: SQLBackend) =
  ## Truncate all tables
  self.db_exec(sql"DELETE FROM user")
  self.db_exec(sql"DELETE FROM role")
  self.db_exec(sql"DELETE FROM pending_registration")
