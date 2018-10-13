#
# Nim HTTP Authentication and Authorization - email
#
# Copyright 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file

# Compile with -d:ssl to support SSL
# STARTTLS is not supported

import smtp
import asyncdispatch
import strutils
from nativesockets import Port

from base import Mailer

when defined(mock_send_email):
  type MockMsg* = tuple[sender: string, rcpt: seq[string], msg: string]
  var mock_email_spool*: seq[MockMsg] = @[]

proc newMailer*(smtp_server_addr="localhost", smtp_server_port=587.Port,
    username="", password="", use_tls=true, sender_email_addr="localhost"): Mailer =
  ## Create SMTP Mailer
  result = Mailer(smtp_server_addr: smtp_server_addr,
    smtp_server_port: smtp_server_port,    username: username, password: password,
    use_tls: use_tls, sender_email_addr: sender_email_addr, connected: false
  )
  assert result.sender_email_addr != ""
  result.client = newAsyncSmtp(useSsl=use_tls)


proc send_email*(self: Mailer, recipient, subject, message: string) {.async.} =
  ## Asynchronously send email using SMTP
  let recipients = @[recipient]
  let encoded = createMessage(subject, message, recipients, @[], [])

  when defined(mock_send_email):
    let m = (self.sender_email_addr, recipients, $encoded)
    mock_email_spool.add m
    return

  if not self.connected:
    await self.client.connect(self.smtp_server_addr, self.smtp_server_port)
  if self.username != "":
    await self.client.auth(self.username, self.password)
  await self.client.sendMail(self.sender_email_addr, recipients, $encoded)
  await self.client.close()
