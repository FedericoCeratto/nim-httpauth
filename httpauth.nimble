# Package

version       = "0.3.0"
author        = "Federico Ceratto"
description   = "HTTP Authentication and Authorization"
license       = "LGPLv3"

bin           = @["httpauth"]

# Dependencies

requires "nim >= 0.19.0", "libsodium"

# Tested with dependencies:
# redis 0.3.0
