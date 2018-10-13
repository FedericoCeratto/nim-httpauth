#
# Nim HTTP Authentication and Authorization
#
# Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file

from nativesockets import Port
from smtp import AsyncSmtp
from times import DateTime

type
  AuthError*  = object of Exception ## Generic Authentication/Authorization exception
  LoginError* = object of AuthError ## Incorrect username/password pair or inexistent user
  UserExistsError* = object of AuthError    ## User already exists
  UserNotFoundError* = object of AuthError  ## User not found
  RoleExistsError* = object of AuthError    ## Role already exists
  RoleNotFoundError* = object of AuthError  ## Role not found
  PendingRegistrationNotFoundError* = object of AuthError  ## Pending Reg. not found
  LevelError* = object of AuthError         ## Incorrect level
  BackendIOError* = object of AuthError

  HTTPAuthBackend* = ref object of RootObj
  User* = ref object of RootObj
    username*, role*, description*, email_addr*: string
    hash*: string
    creation_date*, last_login*: DateTime
    level*: int
  Role* = ref object of RootObj
    name*: string
    level*: int
  PendingRegistration* = ref object of RootObj
    username*, role*, email_addr*, description*, hash*: string
    creation_date*: DateTime
  Mailer* = ref object of RootObj
    smtp_server_addr*: string
    smtp_server_port*: Port
    username*: string
    password*: string
    use_tls*: bool
    client*: AsyncSmtp
    sender_email_addr*: string
    connected*: bool

proc `$`*(r: Role): string =
  ##
  # FIXME
  ""

proc `$`*(r: PendingRegistration): string =
  ##
  # FIXME
  ""

# Backend

{.push base.}

method get_user*(self: HTTPAuthBackend, username: string): User = discard

method get_user_by_email*(self: HTTPAuthBackend, email_addr: string): User = discard

method set_user*(self: HTTPAuthBackend, user: User) = discard

method delete_user*(self: HTTPAuthBackend, username: string) = discard

method save_users*(self: HTTPAuthBackend) = discard

method count_users*(self: HTTPAuthBackend): int = discard

method list_users*(self: HTTPAuthBackend): seq[User] = discard


method get_role*(self: HTTPAuthBackend, rolename: string): Role = discard

method set_role*(self: HTTPAuthBackend, role: Role) = discard

method delete_role*(self: HTTPAuthBackend, rolename: string) = discard

method save_roles*(self: HTTPAuthBackend) = discard

method count_roles*(self: HTTPAuthBackend): int = discard

method list_roles*(self: HTTPAuthBackend): seq[Role] = discard


method get_pending_registration*(self: HTTPAuthBackend, registration_code: string
  ): PendingRegistration = discard

method set_pending_registration*(self: HTTPAuthBackend,
  registration_code: string, registration: PendingRegistration) = discard

method delete_pending_registration*(self: HTTPAuthBackend, registration_code: string
  ) = discard

method save_pending_registrations*(self: HTTPAuthBackend) = discard

method save_pending_re*(self: HTTPAuthBackend) = discard

method count_pending_registrations*(self: HTTPAuthBackend): int = discard

method list_pending_registrations*(self: HTTPAuthBackend): seq[PendingRegistration] = discard


method purge_all_tables*(self: HTTPAuthBackend) = discard

method shutdown*(self: HTTPAuthBackend) = discard

{.pop.}
