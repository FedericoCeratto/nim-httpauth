# Package

version       = "0.1.0"
author        = "Federico Ceratto"
description   = "HTTP Authentication and Authorization"
license       = "LGPLv3"

bin           = @["httpauth"]

# Dependencies

requires "nim >= 0.15.2", "libsodium"
