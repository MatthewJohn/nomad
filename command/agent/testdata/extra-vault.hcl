# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# this unnamed (default) config should merge cleanly onto the basic config
vault {
  enabled = true
  token   = "abracadabra"
}

# these alternate configs should be added as an extra vault configs
vault {
  name                  = "alternate"
  address               = "[0:0::1F]:9501"
  allow_unauthenticated = true
  task_token_ttl        = "5s"
  enabled               = true
  token                 = "xyzzy"
  ca_file               = "/path/to/ca/file"
  ca_path               = "/path/to/ca"
  cert_file             = "/path/to/cert/file"
  key_file              = "/path/to/key/file"
  tls_server_name       = "barbaz"
  tls_skip_verify       = true
  create_from_role      = "test_role2"
}

vault {
  name    = "other"
  address = "127.0.0.1:9502"

  default_identity {
    aud = ["vault-other.io"]
    ttl = "4h"
  }
}
