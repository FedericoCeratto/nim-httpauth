## Nim HTTP Authentication and Authorization - end-to-end tests
## Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
## Released under LGPLv3 License, see LICENSE file

from os import joinPath
import strutils

const
  test_admin_password* = "hunter123"
  test_basedir* = "/tmp/test_httpauth"
  test_db_fname* = joinPath(test_basedir, "integ_server.sqlite3")
  db_uri* = "sqlite://$#" % test_db_fname
