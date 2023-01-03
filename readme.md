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

## Functionality

### Token Metadata

We follow the FA2 standard for the metadata specification. The tzip 16 standard allows to extend the metadata with arbitrary fields. As per CMTA we are using the following mapping.

Mandatory attributes, applicable to all CMTAT tokens:

| Specification | Metadata Key |
|----------|:-------------:|
| Name |  name |
| Ticker symbol (optional) |  symbol |
| Token ID (ISIN or other identifier) (optional) |  fa2 has by default a token ID |
| Reference to the terms of tokenization, the terms of the instrument, and other relevant documents (e.g. prospectus or key information document). The reference can take the form of an URL, a combination of an URL and of specific directions allowing the user to retrieve the relevant documents (e.g. "[domain].com/shares > Tokens") or a fingerprint.  |  terms |
| Note that decimals number must be set to zero (which means that the tokens admit no fractional parts). |  decimals always set to 0 |

Optional attributes, applicable to tokens used for debt securities:

| Specification | Metadata Key |
|----------|:-------------:|
| Guarantor identifier (if any) |  guarantor |
| Bondholder representative identifier (if any) | bondholder |
| Maturity date | maturityDate |
| Interest rate | interestRate |
| Par value (principal amount) | parValue |
| Interest schedule format (if any). The purpose of the interest schedule is to set, in the parameters of the smart contract, the dates on which the interest payments accrue.<br>Format A: start date/end date/period<br>Format B: start date/end date/day of period (e.g. quarter or year)<br>Format C: date 1/date 2/date 3/…. | interestSchedule |
| Interest payment date (if different from the date on which the interest payment accrues:<br>Format A: period (indicating the period between the accrual date for the interest payment and the date on which the payment is scheduled to be made)<br>Format B: specific date | interestPaymentDate |
| Day count convention | dayCountConvention |
| Business day convention | businessDayConvention |
| Public holidays calendar | publicHolidaysCalendar | 

You can find a sample token metadata in the metadata folder. Once uploaded to either a static url or IPFS you can simply convert the UTF8 string of the URI to bytes and set said bytes in the `set_token_metadata` entrypoint. 

### Rule Engine

This reference implementation can either be extended/adapted by code. Or another option if the customization is only on the transferrability you can implement and set a `rule_contract`. If a rule contract is set, it needs to provide a `validate_transfer(transfer: Transfer)` entrypoint, this entrypoint will be invoked on transfer, it if passes the the transfer will go throuhgh, if it fails however the transfer is rolled back.

The rule engine can be used for usecases like freezing or KYC/DID checks.

### Snapshots

The contract allows to create on-chain snapshots which are implemented in an computationally efficient way for entrypoints with state changes (no loops). Only viewing the snapshot has a loop which scales linearly with the number of snapshots (per token).

The admin of a specific token can schedule 1 snapshot for the future (for that token) using the `schedule_snapshot` entrypoint. A schedule can be overwritten with a new value by re-calling the same entrypoint with a new timestamp as parameter.

On chain you can check the snapshot values by consuming the views `view_snapshot_total_supply` and `view_snapshot_balance_of`.

## Entrypoints
### `transfer(self, transfers)`

Sligthly adapted FA2 transfer method which includes pause, rule engine and snapshot functionality

### `set_identity(self, identity)`

Allows a user to set the own identity

### `kill(self)`

Wipes irreversebly the storage and ultimately kills the contract such that it can no longer be used. All tokens on it will be affected. Only special admin of token id 0 can do this.

### `unschedule_snapshot(self, token_id)`

Unschedules the scheduled snapshot for the given token_id. Only token administrator can do this. 

### `schedule_snapshot(self, token_id, snapshot_timestamp)`

Schedules a snapshot for the future for a specific token. Only one snapshot can be scheduled, repeated call will overwrite a future snapshot to the new value. Only token administrator can do this.

### `delete_snapshot(self, snapshot_lookup_key)`
Deletes a snapshot for the given snapshot lookup key (consisting of token_id = sp.TNat, snapshot_timestamp = sp.TTimestamp). Only token administrator can do this.

### `set_rule_engines(self, rules)`

Allows to specify the rules contract for a specific token, only a token administrator can do this

### `unpause(self, token_ids)`

Allows to unpause tokens, only a token administrator can do this

### `pause(self, token_ids)`

Allows to pause tokens, only a token administrator can do this

### `burn(self, token_amounts)`

Allows to burn tokens on the defined recipient address, only a token administrator can do this

### `mint(self, token_amounts)`

Allows to mint new tokens to the defined recipient address, only a token administrator can do this

### `initialise_token(self, token_ids)`

Initialise the token with the required additional token context, can only be called once per token and only one of its admin can call this

### `remove_administrator(self, token_id, administrator_to_remove)`

This removes a administrator entry entirely from the map

### `set_administrator(self, token_id)`

Only a proposed admin can call this entrypoint. If the sender is correct the new admin is set
    
### `propose_administrator(self, token_id, proposed_administrator)`

This kicks off the adding of a new administrator for a specific token. First you propose and then the proposed admin can set him/herself with the set_administrator endpoint

### `set_token_metadata(self, token_metadata_list)`

The definition of a new token requires its metadata to be set. Only the administrators of a certain token can edit existing. If no token metadata is set for a given ID the sender will become admin of that token automatically

### `balance_of(self, balance_of_request)`

As per FA2 standard, takes balance_of requests and reponds on the provided callback contract
    
### `update_operators(self, update_operators)`

As per FA2 standard, allows a token owner to set an operator who will be allowed to perform transfers on her/his behalf

## Views

### `view_total_supply(self, token_id)`

Given a token id allows the consumer to view the current total supply.
    
### `view_balance_of(self, ledger_key)`

Given a ledger key (consisting of token_id = sp.TNat, owner = sp.TAddress) allows the consumer to view the current balance.
    
### `view_current_snapshot(self, token_id)`

Given a token id allows the consumer to view the current snapshot timestamp. Can be null. 
    
### `view_next_snapshot(self, token_id)`

Given a token id allows the consumer to view the next snapshot timestamp. Can be null.ß

### `view_snapshot_balance_of(snapshot_ledger_key)`

Given the snapshot ledger key (consisting of token_id = sp.TNat, owner = sp.TAddress, snapshot_timestamp = sp.TTimestamp) allows the consumer to retrieve the balance in nat of a given snapshot.

### `view_snapshot_total_supply(self, snapshot_lookup_key)`

Given the snapshot lookup key (consisting of token_id = sp.TNat, snapshot_timestamp = sp.TTimestamp) allows the consumer to retrieve the total supply in nat of a given snapshot.

## Build/Basic Usage

### Dependencies

This project depends only on SmartPy, you can install SmartPy by doing a:

```
$ sh <(curl -s https://smartpy.io/cli/install.sh)
```

You can read more about the installation here: https://smartpy.io/cli/

If you feel lazy you can simply copy/paste the entire 'cmta_fa2.py' content into the web IDE: https://smartpy.io/ide 

### Build

```
$ /home/coder/smartpy-cli/SmartPy.sh compile cmta_fa2.py "CMTAFA2()" out
```

### Test
```
$ /home/coder/smartpy-cli/SmartPy.sh test cmta_fa2.py out
```

