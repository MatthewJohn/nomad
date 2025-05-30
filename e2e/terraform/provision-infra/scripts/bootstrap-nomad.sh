#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

while true :
do
    ROOT_TOKEN=$(nomad acl bootstrap | awk '/Secret ID/{print $4}')
    if [ ! -z $ROOT_TOKEN ]; then break; fi
    sleep 5
    pwd
    echo NOMAD_ADDR= $NOMAD_ADDR
    echo NOMAD_CACERT= $NOMAD_CACERT
    pwd
done
set -e

export NOMAD_TOKEN="$ROOT_TOKEN"

mkdir -p "$NOMAD_TOKEN_PATH"
echo $NOMAD_TOKEN > "${NOMAD_TOKEN_PATH}/nomad_root_token"
echo NOMAD_TOKEN=$NOMAD_TOKEN

# Our default policy after bootstrapping will be full-access. Without
# further policy, we only test that we're hitting the ACL code
# Tests can set their own ACL policy using the management token so
# long as they clean up the ACLs afterwards.
nomad acl policy apply \
      -description "Anonymous policy (full-access)" \
      anonymous \
      "${DIR}/anonymous.nomad_policy.hcl"

echo "Nomad successfully bootstraped"
