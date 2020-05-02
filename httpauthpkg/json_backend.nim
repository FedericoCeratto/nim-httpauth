#
## Nim HTTP Authentication and Authorization - JSON Backend
#
# Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file

## The backend is designed for single-host web applications
## with infrequent changes to the authentication datastore.
## The datastore is lock-free and its contents are buffered
## in memory to avoid reading from disk. Multithreading
## and multiprocessing are not supported.

import json,
  os,
  strutils,
  tables,
  logging

from marshal import to
from sequtils import allIt

import base

type
  Users =  Table[string, User]
  Roles = Table[string, Role]
  PendingRegistrations = Table[string, PendingRegistration]

  JsonBackend* = ref object of HTTPAuthBackend
    directory, users_fname, roles_fname, pending_registrations_fname: string
    users*: Table[string, User]
    roles*: Roles
    pending_registrations*: PendingRegistrations

#[
# write
var jout = newJArray()
for u in values(users):
  var j = %* {
    "name": u.username,
    "role": u.role,
    "desc": u.description,
    "e": u.email_addr,
    "h": u.hash
  }
  jout.add(j)

fn.writeFile($jout)
]#

import times


proc load_users_file(self: JsonBackend) =
  let fn = self.users_fname
  var users = initTable[string, User]()
  try:
    for node in items(parseFile(fn)):
      let cdate = node["cdate"].getInt().fromUnix().utc()
      let ldate = node["ldate"].getInt().fromUnix().utc()
      let u = User(
        username: node["name"].str,
        role: node["role"].str,
        description: node["desc"].str,
        email_addr: node["e"].str,
        hash: node["h"].str,
        creation_date: cdate,
        last_login: ldate,
      )
      users.add(node["name"].str, u)
  except Exception:
    raise newException(Exception,
      "Unable to read or parse JSON file $#: $#" % [fn, getCurrentExceptionMsg()])
  self.users = users

proc load_roles_file(self: JsonBackend) =
  let fn = self.roles_fname
  echo "---"
  echo fn.readFile
  echo "---"
  echo "paresed ", parseFile(fn)
  echo "-<>-"
  var roles = initTable[string, Role]()
  try:
    for node in items(parseFile(fn)):
      roles.add(node["name"].str, Role(
        level: node["l"].getInt().int,
      ))
  except Exception:
    raise newException(Exception,
      "Unable to read or parse JSON file $#: $#" % [fn, getCurrentExceptionMsg()])
  self.roles = roles

proc load_pending_registrations_file(self: JsonBackend) =
  let fn = self.pending_registrations_fname
  var pending_registrations = initTable[string, PendingRegistration]()
  try:
    for node in items(parseFile(fn)):
      let cdate = node["cdate"].getInt().fromUnix().utc()
      pending_registrations.add(node["name"].str, PendingRegistration(
        username: node["name"].str,
        role: node["role"].str,
        email_addr: node["e"].str,
        description: node["desc"].str,
        hash: node["h"].str,
        creation_date: cdate,
      ))
  except Exception:
    raise newException(Exception,
      "Unable to read or parse JSON file $#: $#" % [fn, getCurrentExceptionMsg()])
  self.pending_registrations = pending_registrations


proc load_json_files(self: JsonBackend) =
  ## Load JSON files located under self.directory
  self.load_users_file()
  self.load_roles_file()
  self.load_pending_registrations_file()


proc newJsonBackend*(directory: string, users_fname="users.json", roles_fname="roles.json",
    pending_registrations_fname="pending_registrations.json"): JsonBackend =
  ## Initialize JsonBackend
  ## Handles JSON files. Multithreading and multiprocessing are not supported.
  ## If none of the DB files is present all of them will be created.
  var self = JsonBackend(
    users: initTable[string, User](),
    roles: initTable[string, Role](),
    pending_registrations: initTable[string, PendingRegistration](),
    users_fname: directory / users_fname,
    roles_fname: directory / roles_fname,
    pending_registrations_fname: directory / pending_registrations_fname
  )

  createDir(directory)
  let fns = @[self.users_fname, self.roles_fname, self.pending_registrations_fname]
  if allIt(fns, not it.existsFile()):
    for fn in fns:
      info "Creating DB file $#" % fn
      #FIXME logging
      echo "Creating DB file $#" % fn
      fn.writeFile("[]")

  self.load_json_files()
  return self

proc save_file(fname: string, json_str: string) =
  ## Write to disk atomically
  let tmp_fname = fname & ".tmp"
  try:
    tmp_fname.writefile(json_str)
    moveFile(tmp_fname, fname)
  except Exception:
    raise newException(BackendIOError,
      "Unable to save JSON file $#: $#" % [fname, getCurrentExceptionMsg()])

method save_users*(self: JsonBackend) =
  ## Save users in a JSON file
  var jout = newJArray()
  for i in self.users.values:
    for u in values(self.users):
      var j = %* {
        "name": u.username,
        "role": u.role,
        "desc": u.description,
        "e": u.email_addr,
        "h": u.hash
      }
      jout.add(j)

  save_file(self.users_fname, $jout)

proc save_roles(self: JsonBackend) =
  ## Save roles in a JSON file
  save_file(self.roles_fname, $self.roles)

proc save_pending_registrations(self: JsonBackend) =
  ## Save pending registrations in a JSON file
  save_file(self.pending_registrations_fname, $self.pending_registrations)

method get_user*(self: JsonBackend, username: string): User =
  ## Get User
  if not self.users.hasKey(username):
    raise newException(AuthError, "User is not existing")
  return self.users[username]

method set_user*(self: JsonBackend, username: string, user: User) =
  ## Set User
  discard

method get_role*(self: JsonBackend, rolename: string): Role =
  ## Get Role
  return self.roles[rolename]

proc initialize_storage(self: JsonBackend) =
  ## Create initial JSON files
  self.users.clear()
  self.roles.clear()
  self.pending_registrations.clear()
  self.save_users()
  self.save_roles()
  self.save_pending_registrations()


method purge_all_tables*(self: JsonBackend) = discard
  #FIXME
