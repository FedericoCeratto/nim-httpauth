## Enhanced HTTP client with cookie jar
## Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
## Released under LGPLv3 License, see LICENSE file

import httpclient,
  strtabs,
  strutils,
  tables,
  times

import httpauthpkg/cookiejar

type
  Cookie = object of RootObj
    name*, value*, domain*, path*: string
    host_only*, secure*, http_only*: bool
    expires*: Time

  HttpTestClient = object of RootObj
    proto, domain, baseurl: string
    client: HttpClient
    cookiejar*: CookieJar

proc newHttpTestClient*(proto, domain: string, timeout=500): HttpTestClient =
  ## Initialize HttpTestClient
  result = HttpTestClient(proto:proto, domain:domain)
  result.client = newHttpClient(timeout=timeout)
  result.baseurl = "$#://$#" % [proto, domain]
  result.domain = domain
  result.cookiejar = newCookieJar()

export body

proc get*(self: var HttpTestClient, relurl:string): Response =
  ## GET
  assert relurl.startswith("/")
  echo "-- get ", relurl
  # FIXME set domain from self.domain - handle port numbers!
  let ch = self.cookiejar.get_cookies("localhost", relurl, secure=true)
  self.client.headers = newHttpHeaders({
    "Cookie": ch
  })
  result = self.client.get(self.baseurl & relurl)
  # reset headers after every call
  self.client.headers.clear()

  if result.headers.hasKey("set-cookie"):
    # https://github.com/nim-lang/Nim/issues/5611
    let cookies: seq[string] = result.headers.table["set-cookie"]
    self.cookiejar.add_cookies(cookies, self.domain, relurl)

proc postmp*(self: var HttpTestClient, relurl:string, a: openArray[(string, string)]): Response =
  ## POST
  assert relurl.startswith("/")
  var data = newMultipartData()
  for i in items(a):
    data[i[0]] = i[1]

  return self.client.post(self.baseurl & relurl, multipart=data)

proc post*(self: var HttpTestClient, relurl:string, a: openArray[(string, string)]): Response =
  ## POST
  assert relurl.startswith("/")
  echo "-- post ", relurl
  var body=""
  for i in items(a):
    if body.len != 0:
      body.add "&"
    body.add "$#=$#" % [i[0], i[1]]

  # FIXME set domain from self.domain - handle port numbers!
  let ch = self.cookiejar.get_cookies("localhost", relurl, secure=true)
  self.client.headers = newHttpHeaders({
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "Cookie": ch
  })

  let resp = self.client.post(
    self.baseurl & relurl,
    body=body,
  )
  # reset headers after every call
  self.client.headers.clear()

  if resp.headers.hasKey("set-cookie"):
    # https://github.com/nim-lang/Nim/issues/5611
    let cookies: seq[string] = resp.headers.table["set-cookie"]
    self.cookiejar.add_cookies(cookies, self.domain, relurl)

  return resp
