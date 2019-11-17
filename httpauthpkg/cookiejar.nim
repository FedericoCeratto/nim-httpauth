## Cookie jar
## Copyright 2017 Federico Ceratto <federico.ceratto@gmail.com>
## Released under LGPLv3 License, see LICENSE file

import strutils,
  tables,
  times

type
  Cookie* = object of RootObj
    name*, value*, domain*, path*: string
    host_only*, secure*, http_only*, session*: bool
    # expires should be ignored when session==true
    expires*: Time

  CookieJar* = ref object of RootObj
    # domain -> cookie_name -> cookie
    cookietable: Table[string, Table[string, Cookie]]


proc parseSetCookie*(header: string): Cookie =
  ## Parse Set-Cookie header
  result = Cookie(session: true)
  var i = 0
  if header[0..11].toLowerAscii == "set-cookie: ":
    i = 12  # skip header

  let le = header.len

  # get to the cookie name
  while header[i] == ' ': inc i

  # extract name
  let name_start = i
  while header[i] != '=' and i < le: inc i
  result.name = substr(header, name_start, i-1)
  if i == le: return

  # extract value - anything other than ";"
  # more permissive than the RFC
  inc i # skip "="
  let value_start = i
  while header[i] != ';' and i < le: inc i
  result.value = substr(header, value_start, i-1)

  while true:
    if i == le: return
    inc i # skip ';'
    while header[i] == ' ' and i < le: inc i
    let key_start = i
    # walk to ';' or '=' or the end
    while header[i] != ';' and header[i] != '=' and i < le: inc i
    let key = substr(header, key_start, i-1).toLowerAscii
    var val = ""
    if header[i] == '=':
      inc i # skip '='
      while header[i] == ' ' and i < le: inc i
      let val_start = i
      # walk to ';' or the end
      while header[i] != ';' and i < le: inc i
      val = substr(header, val_start, i-1)

    case key
    of "domain":
      if val.startswith("."):
        result.domain = val[1..^1]
      else:
        result.domain = val
    of "path":
      result.path = val
    of "httponly":
      result.http_only = true
    of "expires":
      if not (val.endswith(" GMT") or val.endswith(" UTC")):
        continue
      result.session = false
      var exp = parse(val, "ddd, dd MMM yyyy HH:mm:ss",
        zone=utc()
      )
      #         parse(v, "ddd, dd MMM yy HH:mm:SS")
      doAssert exp.isDST == false
      #doAssert exp.timezone == 3#<F2> newTimezone("Etc/UTC")
      result.expires = toTime exp
    of "secure":
      result.secure = true
    of "max-age":
      try:
        result.expires = getTime() + seconds(parseInt(val))
      except:
        discard
    else:
      # unexpected
      discard



proc newCookieJar*(): CookieJar =
  ## init CookieJar
  result = CookieJar()
  result.cookietable = initTable[string, Table[string, Cookie]]()

proc add_cookies*(jar: var CookieJar, raw_cookies: seq[string], domain, path: string) =
  ## Add one or more cookies to the jar
  for rc in raw_cookies:
    var cookie = parseSetCookie(rc)

    if cookie.domain == "":
      cookie.domain = domain
      cookie.host_only = true

    if cookie.path == "":
      cookie.path = path

    if cookie.session or (cookie.expires > getTime()):
      if not jar.cookietable.hasKey(cookie.domain):
        var t = initTable[string, Cookie]()
        jar.cookietable[cookie.domain] = initTable[string, Cookie]()

      jar.cookietable[cookie.domain][cookie.name] = cookie

    else:
      ## Do not add cookie, and delete if already in the jar
      if jar.cookietable.hasKey(cookie.domain):
        if jar.cookietable[cookie.domain].hasKey(cookie.name):
          del(jar.cookietable[cookie.domain], cookie.name)

        if jar.cookietable[cookie.domain].len == 0:
          del(jar.cookietable, cookie.domain)

proc get_cookies*(jar: CookieJar, domain, path: string, secure=false): string =
  ## Get cookies to be sent to a server
  ## Secure cookies are returned only when secure==true
  ## Expired cookies are removed
  result = ""
  let domain_chunks = domain.split('.')
  let now = getTime()
  for depth in 1..domain_chunks.len:
    # walk up - this will look up for TLDs eventually, hopefully without
    # finding anything. Needed to match local names.
    let partial_domain = domain_chunks[depth-1..^1].join(".")
    if jar.cookietable.hasKey(partial_domain):
      for c in values jar.cookietable[partial_domain]:
        if not secure and c.secure:
          continue
        if not c.session and (c.expires < now):
          echo "DROPPING old cookie"
          del(jar.cookietable[c.domain], c.name)
        else:
          result.add "$#=$#;" % [c.name, c.value]


proc clear*(jar: CookieJar) =
  ## Empty the jar
  jar.cookietable.clear()

proc count*(jar: CookieJar): int =
  ## Count cookies
  for v in values jar.cookietable:
    result.inc v.len

proc pprint*(jar: CookieJar) =
  ## Pretty-print cookies
  for domain, cookies in pairs jar.cookietable:
    echo ""
    echo domain
    for c in values cookies:
      var line = "  Name: $# Value: $# Path: '$#'" % [c.name, c.value, c.path]
      if c.http_only: line.add " HttpOnly"
      if c.secure: line.add " Secure"
      if not c.session: line.add " Expires: $#" % $c.expires
      echo line
  echo ""
