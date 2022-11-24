# CMTA FA2 Blueprint Implementation

This reference implementation provides an easy to use Tezos Token smart contract following
the FA2 standard defined [here](https://gitlab.com/tzip/tzip/-/blob/master/proposals/tzip-12/).
[Capital Markets and technology association](https://www.cmta.ch/) (CMTA) has provided guideance 
on implementing the required functionalities in order to tokeniza a Swiss corporation's equity
securities. The blueprint document can be found here [Blueprint](https://cmta.ch/content/15de282276334fc837b9687a13726ab9/cmtat-functional-specifications-jan-2022-final.pdf)  

This implementation derived the required functionality from the [CMTAT project](https://github.com/CMTA/CMTAT). 

There are two main differences compared to the mentioned CMTAT project:

- FA2 allows for multiple tokens on the same contract. This of course means that we can have per token
an admin who gets the token 'owner' status as per CMTAT. Since 'owner' in FA2 receives another sematic
 we a use the expression 'token admin' to relate to the 'CMTAT token owner' and 'token owners' for us
 are what CMTAT calls 'holders'.
- For gas optimization purposes where it makes sense the entrypoints have been extended to accept lists. 
This allows for batched operations. 

## Glossary
 - Owner (CMTAT):        the administrator of a specific token_id (one per token_id).
 - Holder (CMTAT):       the token holder (n per token_id). In our context the actual shareholder.
 - Administrator:         the administrator of a specific token_id (one per token_id).
 - Owner:                 the token holder (n per token_id). In our context the actual shareholder.
 - Batch:                 allow for multiple changes/executions in one method call. Will always fail for all requests (and revert) in case a single one fails. 
 - Contact:               contact data in bytes. This can be encrypted or unencrypted. Used for shareholder identity (recommended encrypted/not accessible for everyone) and/or token contact (readable for everyone) for shareholders.
 - Plurals:               plurals are used in the variable name to signal a list. If the plural does not make sense, we choose the _list postfix. 

## Build/Basic Usage

### Dependencies

This project depends only on SmartPy, you can install SmartPy by doing a:

```
$ sh <(curl -s https://smartpy.io/cli/install.sh)
```

You can read more about the installation here: https://smartpy.io/cli/

If you feel lazy you can simply copy/paste the entire 'cmtaFA2.py' content into the web IDE: https://smartpy.io/ide 

### Build

```
$ /home/coder/smartpy-cli/SmartPy.sh compile cmtaFA2.py "CMTAFA2()" out
```

### Test
```
$ /home/coder/smartpy-cli/SmartPy.sh test cmtaFA2.py out
```

### Rule Engine

This reference implementation can either be extended/adapted by code. Or another option if the customization is only on the transferrability you can implement and set a `rule_contract`. If a rule contract is set, it needs to provide a `can_transfer(transfer: Transfer)` entrypoint, this entrypoint will be invoked on transfer, it if passes the the transfer will go throuhgh, if it fails however the transfer is rolled back.