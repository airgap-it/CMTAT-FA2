"""
# CMTA FA2 Blueprint Implementation

This reference implementation provides an easy to use Tezos Token smart contract following
the FA2 standard defined [here](https://gitlab.com/tzip/tzip/-/blob/master/proposals/tzip-12/).
[Capital Markets and technology association](http://www.cmta.ch/) (CMTA) has provided guideance 
on implementing the required functionalities in order to tokeniza a Swiss corporation's equity
securities. The blueprint document can be found here [Blueprint]( https://www.cmta.ch/content/52/cmta-blueprint-for-the-tokenization-of-shares-of-swiss-corporations.pdf)  

This implementation derived the required functionality from the [CMTA20 project](https://github.com/CMTA/CMTA20). 

There are two main differences compared to the mentioned CMTA20 project:

- FA2 allows for multiple tokens on the same contract. This of course means that we can have per token
an admin who gets the token 'owner' status as per CMTA20. Since 'owner' in FA2 receives another sematic
 we a use the expression 'token admin' to relate to the 'CMTA20 token owner' and 'token owners' for us
 are what CMTA20 calls 'holders'.
- For gas optimization purposes where it makes sense the entrypoints have been extended to accept lists. 
This allows for batched operations. 

## Glossary
 - Owner (CMTA20):        the administrator of a specific token_id (one per token_id).
 - Holder (CMTA20):       the token holder (n per token_id). In our context the actual shareholder.
 - Administrator:         the administrator of a specific token_id (one per token_id).
 - Owner:                 the token holder (n per token_id). In our context the actual shareholder.
 - Batch:                 allow for multiple changes/executions in one method call. Will always fail for all requests (and revert) in case a single one fails. 
 - Contact:               contact data in bytes. This can be encrypted or unencrypted. Used for shareholder identity (recommended encrypted/not accessible for everyone) and/or token contact (readable for everyone) for shareholders.
 - Plurals:               plurals are used in the variable name to signal a list. If the plural does not make sense, we choose the _list postfix. 
"""
import smartpy as sp

NULL_ADDRESS = sp.address("tz1YtuZ4vhzzn7ssCt93Put8U9UJDdvCXci4")
NULL_BYTES = sp.bytes('0x')

class FA2ErrorMessage:
    """Static enum used for the FA2 related errors, using the `FA2_` prefix"""
    PREFIX = "FA2_"
    TOKEN_UNDEFINED = "{}TOKEN_UNDEFINED".format(PREFIX)
    """This error is thrown if the token id used in to defined"""
    INSUFFICIENT_BALANCE = "{}INSUFFICIENT_BALANCE".format(PREFIX)
    """This error is thrown if the source address transfers an amount that exceeds its balance"""
    NOT_OWNER = "{}_NOT_OWNER".format(PREFIX)
    """This error is thrown if not the owner is performing an action that he/she shouldn't"""
    NOT_OPERATOR = "{}_NOT_OPERATOR".format(PREFIX)
    """This error is thrown if neither token owner nor permitted operators are trying to transfer an amount"""

class TokenMetadata:
    """Token metadata object as per FA2 standard"""
    def get_type():
        """Returns a single token metadata type, layouted"""
        return sp.TRecord(token_id = sp.TNat, token_metadata = sp.TMap(sp.TString, sp.TBytes)).layout(("token_id", "token_metadata"))
    def get_batch_type():
        """Returns a list type containing token metadata types"""
        return sp.TList(TokenMetadata.get_type())
        
class Transfer:
    """Transfer object as per FA2 standard"""
    def get_type():
        """Returns a single transfer type, layouted"""
        tx_type = sp.TRecord(to_ = sp.TAddress,
                             token_id = sp.TNat,
                             amount = sp.TNat).layout(
                ("to_", ("token_id", "amount"))
            )
        transfer_type = sp.TRecord(from_ = sp.TAddress,
                                   txs = sp.TList(tx_type)).layout(
                                       ("from_", "txs"))
        return transfer_type
    
    def get_batch_type():
        """Returns a list type containing transfer types"""
        return sp.TList(Transfer.get_type())
    
    def item(from_, txs):
        """Creates a typed transfer item"""
        return sp.set_type_expr(sp.record(from_ = from_, txs = txs), Transfer.get_type())

class UpdateOperator():
    """Update operators object as per FA2 standard"""
    def get_operator_param_type():
        """Parameters included in the update operator request"""
        return sp.TRecord(
            owner = sp.TAddress,
            operator = sp.TAddress,
            token_id = sp.TNat
            ).layout(("owner", ("operator", "token_id")))
    
    def get_type():
        """Returns a single update operator type, layouted"""
        return sp.TVariant(
                    add_operator = UpdateOperator.get_operator_param_type(),
                    remove_operator = UpdateOperator.get_operator_param_type())

    def get_batch_type():
        """Returns a list type containing update operator types"""
        return sp.TList(UpdateOperator.get_type())

class BalanceOf:
    """Balance of object as per FA2 standard"""
    def get_response_type():
        """Returns the balance_of reponse type, layouted"""
        return sp.TList(
            sp.TRecord(
                request = LedgerKey.get_type(),
                balance = sp.TNat).layout(("request", "balance")))
    def get_type():
        """Returns the balance_of type, layouted"""
        return sp.TRecord(
            requests = sp.TList(LedgerKey.get_type()),
            callback = sp.TContract(BalanceOf.get_response_type())
        ).layout(("requests", "callback"))

class LedgerKey:
    """Ledger key used when looking up balances"""
    def get_type():
        """Returns a single ledger key type, layouted"""
        return sp.TRecord(token_id = sp.TNat, owner = sp.TAddress).layout(("token_id", "owner"))
        
    def make(token_id, owner):
        """Creates a typed ledger key"""
        return sp.set_type_expr(sp.record(token_id = token_id, owner = owner), LedgerKey.get_type())

class OperatorKey:
    """Operator key used when looking up operation permissions"""
    def get_type():
        """Returns a single operator key type, layouted"""
        return sp.TRecord(token_id = sp.TNat, owner = sp.TAddress, operator = sp.TAddress ).layout(("token_id", ("owner", "operator")))
        
    def make(token_id, owner, operator):
        """Creates a typed operator key"""
        return sp.set_type_expr(sp.record(token_id = token_id, owner = owner, operator = operator), OperatorKey.get_type())


class BaseFA2(sp.Contract):
    """Base FA2 contract, which implements the required entry points"""
    def get_init_storage(self):
        """Returns the initial storage of the contract"""
        return dict(
            ledger = sp.big_map(tkey=LedgerKey.get_type(), tvalue=sp.TNat),
            token_metadata = sp.big_map(tkey=sp.TNat, tvalue = TokenMetadata.get_type()),
            total_supply = sp.big_map(tkey=sp.TNat, tvalue = sp.TNat),
            operators = sp.big_map(tkey=OperatorKey.get_type(), tvalue = sp.TBool)
        )
    
    def __init__(self):
        """Has no constructor parameters, initialises the storage"""
        self.init(**self.get_init_storage())

    @sp.entry_point
    def transfer(self, transfers):
        """As per FA2 standard, allows a token owner or operator to transfer tokens"""
        sp.set_type(transfers, Transfer.get_batch_type())
        with sp.for_('transfer', transfers) as transfer:
            with sp.for_('tx', transfer.txs) as tx:
                from_user = LedgerKey.make(tx.token_id, transfer.from_)
                to_user = LedgerKey.make(tx.token_id, tx.to_)
                operator_key = OperatorKey.make(tx.token_id, transfer.from_, sp.sender)

                sp.verify(self.data.ledger.get(from_user,sp.nat(0)) >= tx.amount, message = FA2ErrorMessage.INSUFFICIENT_BALANCE)                                     
                sp.verify((sp.sender == transfer.from_) | self.data.operators.get(operator_key, False), message=FA2ErrorMessage.NOT_OWNER)
                
                self.data.ledger[from_user] = sp.as_nat(self.data.ledger[from_user] - tx.amount)
                self.data.ledger[to_user] = self.data.ledger.get(to_user, 0) + tx.amount
                
                with sp.if_(sp.sender != transfer.from_):
                    del self.data.operators[operator_key]
                    
                with sp.if_(self.data.ledger.get(from_user,sp.nat(0)) == sp.nat(0)):
                    del self.data.ledger[from_user]

    @sp.entry_point
    def update_operators(self, update_operators):
        """As per FA2 standard, allows a token owner to set an operator who will be allowed to perform transfers on her/his behalf"""
        sp.set_type(update_operators,UpdateOperator.get_batch_type())
        with sp.for_('update_operator', update_operators) as update_operator:
            with update_operator.match_cases() as argument:
                with argument.match("add_operator") as update:
                    sp.verify(update.owner == sp.sender, message=FA2ErrorMessage.NOT_OWNER)
                    operator_key = OperatorKey.make(update.token_id, update.owner, update.operator)
                    self.data.operators[operator_key] = True
                with argument.match("remove_operator") as update:
                    sp.verify(update.owner == sp.sender, message=FA2ErrorMessage.NOT_OWNER)
                    operator_key = OperatorKey.make(update.token_id, update.owner, update.operator)
                    del self.data.operators[operator_key]

    @sp.entry_point
    def balance_of(self, balance_of_request):
        """As per FA2 standard, takes balance_of requests and reponds on the provided callback contract"""
        sp.set_type(balance_of_request, BalanceOf.get_type())
        
        responses = sp.local("responses", sp.set_type_expr(sp.list([]),BalanceOf.get_response_type()))
        with sp.for_('request', balance_of_request.requests) as request:
            sp.verify(self.data.token_metadata.contains(request.token_id), message = FA2ErrorMessage.TOKEN_UNDEFINED)
            responses.value.push(sp.record(request = request, balance = self.data.ledger.get(LedgerKey.make(request.token_id, request.owner),0)))
            
        sp.transfer(responses.value, sp.mutez(0), balance_of_request.callback)


class AdministratorState:
    """Static enum used for the admin rights and propose flow"""    
    IS_ADMIN = sp.nat(1)
    """This state shows that the admin right is there"""
    IS_PROPOSED_ADMIN = sp.nat(2)
    """This state shows that the admin has been proposed but not full admin yet"""

class AdministrableErrorMessage:
    """Static enum used for the FA2 related errors, using the `FA2_` prefix"""
    PREFIX = "ADM_"
    NOT_ADMIN = "{}NOT_ADMIN".format(PREFIX)

class AdministrableFA2(BaseFA2):
    """FA2 Contract with administrators per token""" 
    def get_init_storage(self):
        """Returns the initial storage of the contract"""
        storage = super().get_init_storage()
        storage['administrator_allowmap'] = sp.set_type_expr(self.administrator_allowmap, sp.TMap(sp.TAddress, sp.TBool))
        storage['administrators'] = sp.big_map(tkey=LedgerKey.get_type(), tvalue = sp.TNat)
        return storage
        
    def __init__(self, administrator_allowmap={}):
        """With the allowmap you can control who can become administrator. If this map is empty then there are no limitations"""
        self.administrator_allowmap = administrator_allowmap
        super().__init__()
    
    @sp.entry_point
    def set_token_metadata(self, token_metadata_list):
        """The definition of a new token requires its metadata to be set. Only the administrators of a certain token can edit existing. 
        If no token metadata is set for a given ID the sender will become admin of that token automatically"""
        sp.set_type(token_metadata_list, TokenMetadata.get_batch_type())
        with sp.for_('token_metadata', token_metadata_list) as token_metadata:
            administrator_ledger_key = LedgerKey.make(token_metadata.token_id, sp.sender)
            with sp.if_(self.data.token_metadata.contains(token_metadata.token_id)):
                sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            with sp.else_():
                with sp.if_(sp.len(self.data.administrator_allowmap)>0):
                    sp.verify(self.data.administrator_allowmap.get(sp.sender, False), message = AdministrableErrorMessage.NOT_ADMIN)
                self.data.administrators[administrator_ledger_key] = AdministratorState.IS_ADMIN    
            self.data.token_metadata[token_metadata.token_id] = token_metadata
    
    @sp.entry_point
    def propose_administrator(self, token_id, proposed_administrator):
        """This kicks off the adding of a new administrator for a specific token. First you propose and then the proposed admin 
        can set him/herself with the set_administrator endpoint"""
        sp.set_type(token_id, sp.TNat)
        sp.set_type(proposed_administrator, sp.TAddress)

        administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
        proposed_administrator_ledger_key = LedgerKey.make(token_id, proposed_administrator)

        sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        self.data.administrators[proposed_administrator_ledger_key] = AdministratorState.IS_PROPOSED_ADMIN

    @sp.entry_point
    def set_administrator(self, token_id):
        """Only a proposed admin can call this entrypoint. If the sender is correct the new admin is set"""
        sp.set_type(token_id, sp.TNat)

        administrator_ledger_key = LedgerKey.make(token_id, sp.sender)

        sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_PROPOSED_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        self.data.administrators[administrator_ledger_key] = AdministratorState.IS_ADMIN
    
    @sp.entry_point
    def remove_administrator(self, token_id, administrator_to_remove):
        """This removes a administrator entry entirely from the map"""
        sp.set_type(token_id, sp.TNat)
        sp.set_type(administrator_to_remove, sp.TAddress)

        administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
        administrator_to_remove_key = LedgerKey.make(token_id, administrator_to_remove)

        sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        del self.data.administrators[administrator_to_remove_key]
    
class Contact:
    def get_type():
        return sp.TRecord(token_id = sp.TNat, contact = sp.TBytes).layout(("token_id", "contact"))
    def get_batch_type():
        return sp.TList(Contact.get_type())

class TokenAmount:
    def get_type():
        return sp.TRecord(token_id = sp.TNat, amount = sp.TNat).layout(("token_id", "amount"))
    def get_batch_type():
        return sp.TList(TokenAmount.get_type())

class Reassignment:
    def get_type():
        return sp.TRecord(token_id = sp.TNat, original_holder = sp.TAddress, replacement_holder = sp.TAddress).layout(("token_id",( "original_holder", "replacement_holder")))
    def get_batch_type():
        return sp.TList(Reassignment.get_type())

class Redemption:
    def get_type():
        return sp.TRecord(token_id = sp.TNat, amount = sp.TNat).layout(("token_id", "amount"))
    def get_batch_type():
        return sp.TList(Redemption.get_type())

class Destruction:
    def get_type():
        return sp.TRecord(token_id = sp.TNat, holders = sp.TList(sp.TAddress)).layout(("token_id", "holders"))
    def get_batch_type():
        return sp.TList(Destruction.get_type())

class TokenId:
    def get_type():
        return sp.TNat
    def get_batch_type():
        return sp.TList(TokenId.get_type())

class Rule:
    def get_type():
        return sp.TRecord(token_id = sp.TNat, rule_contract = sp.TAddress).layout(("token_id", "rule_contract"))
    def get_batch_type():
        return sp.TList(Rule.get_type())
                              
class SnapshotLookupKey:
    def get_type():
        return sp.TRecord(token_id = sp.TNat, snapshot_timestamp = sp.TTimestamp)
    
    def make(token_id, snapshot_timestamp):
        return sp.set_type_expr(sp.record(token_id = token_id, snapshot_timestamp = snapshot_timestamp), SnapshotLookupKey.get_type())

class SnapshotLedgerKey:
    """Snapshot Ledger key used when looking up balances"""
    def get_type():
        """Returns a single ledger key type, layouted"""
        return sp.TRecord(token_id = sp.TNat, owner = sp.TAddress, snapshot_timestamp = sp.TTimestamp).layout(("token_id", ("owner", "snapshot_timestamp")))
        
    def make(token_id, owner, snapshot_timestamp):
        """Creates a typed ledger key"""
        return sp.set_type_expr(sp.record(token_id = token_id, owner = owner,  snapshot_timestamp = snapshot_timestamp), SnapshotLedgerKey.get_type())


class CMTAFA2ErrorMessage:
    """Static enum used for the FA2 related errors, using the `FA2_` prefix"""
    PREFIX = "CM_"
    TOKEN_PAUSED = "{}TOKEN_PAUSED".format(PREFIX)
    TOKEN_EXISTS = "{}TOKEN_EXISTS".format(PREFIX)
    SAME_REASSIGN = "{}SAME_REASSIGN".format(PREFIX)
    CANNOT_TRANSFER = "{}CANNOT_TRANSFER".format(PREFIX)
    SNAPSHOT_IN_PAST = "{}SNAPSHOT_IN_PAST".format(PREFIX)
    SNAPSHOT_ONGOING = "{}SNAPSHOT_ONGOING".format(PREFIX)
        
class CMTAFA2(AdministrableFA2):
    """FA2 Contract blueprint for CMTA tokens""" 
    def get_init_storage(self):
        """Returns the initial storage of the contract"""
        storage = super().get_init_storage()
        storage['snapshot_ledger'] = sp.big_map(tkey=SnapshotLedgerKey.get_type(), tvalue=sp.TNat)
        storage['snapshot_lookup'] = sp.big_map(tkey=SnapshotLookupKey.get_type(), tvalue=sp.TTimestamp)
        storage['token_context'] = sp.big_map(tkey=sp.TNat, tvalue=sp.TRecord(contact=sp.TBytes, is_paused=sp.TBool, can_transfer_rule_contract=sp.TAddress, current_snapshot=sp.TOption(sp.TTimestamp), next_snapshot=sp.TOption(sp.TTimestamp)))
        storage['identities'] = sp.big_map(tkey=sp.TAddress, tvalue=sp.TBytes)
        return storage
        
    def __init__(self, administrator_allowmap={}):
        super().__init__(administrator_allowmap)
        
    # Owner Entrypoints 
    # --- START ---
    @sp.entry_point
    def initialise_token(self, token_ids):
        """Initialise the token with the required additional token context, can only be called once per token and only one of its admin can call this"""
        sp.set_type_expr(token_ids, sp.TList(sp.TNat))

        with sp.for_('token_id', token_ids) as token_id:
            sp.verify((~self.data.token_context.contains(token_id)), message = CMTAFA2ErrorMessage.TOKEN_EXISTS)            
            administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            self.data.token_context[token_id] = sp.record(contact=NULL_BYTES, is_paused=False, can_transfer_rule_contract=NULL_ADDRESS, current_snapshot=sp.none, next_snapshot=sp.none)
        
    @sp.entry_point
    def set_contacts(self, contacts):
        """Allows to set the contact of multiple tokens, only token a administrator can do this"""
        sp.set_type_expr(contacts, Contact.get_batch_type())
        with sp.for_('contact', contacts) as contact:
            token_context = self.data.token_context[contact.token_id]
            administrator_ledger_key = LedgerKey.make(contact.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            token_context.contact = contact.contact
            self.data.token_context[contact.token_id] = token_context

    @sp.entry_point
    def issue(self, token_amounts):
        """Allows to issue new tokens to the calling admin's address, only a token administrator can do this"""
        sp.set_type(token_amounts, TokenAmount.get_batch_type())
        with sp.for_('token_amount', token_amounts) as token_amount:
            administrator_ledger_key = LedgerKey.make(token_amount.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            sp.verify(self.data.token_metadata.contains(token_amount.token_id), message = FA2ErrorMessage.TOKEN_UNDEFINED)
            self.data.ledger[administrator_ledger_key] = self.data.ledger.get(administrator_ledger_key, 0) + token_amount.amount
            self.data.total_supply[token_amount.token_id] = self.data.total_supply.get(token_amount.token_id, 0) + token_amount.amount
    
    @sp.entry_point
    def redeem(self, token_amounts):
        """Allows to redeem tokens on the calling admin's address, only a token administrator can do this"""
        sp.set_type(token_amounts, TokenAmount.get_batch_type())
        with sp.for_('token_amount', token_amounts) as token_amount:
            administrator_ledger_key = LedgerKey.make(token_amount.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            sp.verify(self.data.ledger[administrator_ledger_key]>=token_amount.amount, message = FA2ErrorMessage.INSUFFICIENT_BALANCE)
            self.data.ledger[administrator_ledger_key] = sp.as_nat(self.data.ledger.get(administrator_ledger_key, 0) - token_amount.amount)
            self.data.total_supply[token_amount.token_id] = sp.as_nat(self.data.total_supply.get(token_amount.token_id, 0) - token_amount.amount)
            
            with sp.if_(self.data.ledger[administrator_ledger_key] == 0):
                del self.data.ledger[administrator_ledger_key]
    
    @sp.entry_point
    def reassign(self, reassignments):
        """Allows to reassing tokens on the calling admin's address, only a token administrator can do this"""
        sp.set_type(reassignments, Reassignment.get_batch_type())
        with sp.for_('reassignment', reassignments) as reassignment:
            administrator_ledger_key = LedgerKey.make(reassignment.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            sp.verify(reassignment.original_holder != reassignment.replacement_holder, message = CMTAFA2ErrorMessage.SAME_REASSIGN)
            original_holder_ledger_key = LedgerKey.make(reassignment.token_id, reassignment.original_holder)
            replacement_holder_ledger_key = LedgerKey.make(reassignment.token_id, reassignment.replacement_holder)
            sp.verify(self.data.ledger[original_holder_ledger_key]>sp.nat(0), message = FA2ErrorMessage.INSUFFICIENT_BALANCE)
            self.data.ledger[replacement_holder_ledger_key] = self.data.ledger[original_holder_ledger_key]
            del self.data.ledger[original_holder_ledger_key]
    
    @sp.entry_point
    def destroy(self, destructions):
        """Allows to destroy tokens on the calling admin's address, only a token administrator can do this"""
        sp.set_type(destructions, Destruction.get_batch_type())
        with sp.for_('destruction', destructions) as destruction:
            administrator_ledger_key = LedgerKey.make(destruction.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            with sp.for_('holder', destruction.holders) as holder:
                holder_ledger_key = LedgerKey.make(destruction.token_id, holder)
                sp.verify(self.data.ledger[holder_ledger_key]>sp.nat(0), message = FA2ErrorMessage.INSUFFICIENT_BALANCE)
                self.data.ledger[administrator_ledger_key] = self.data.ledger[holder_ledger_key]
                del self.data.ledger[holder_ledger_key]
                
    @sp.entry_point
    def pause(self, token_ids):
        """Allows to pause tokens, only a token administrator can do this"""
        sp.set_type(token_ids, sp.TList(sp.TNat))
        with sp.for_('token_id', token_ids) as token_id:
            administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            token_context = self.data.token_context[token_id]
            token_context.is_paused = True
            self.data.token_context[token_id] = token_context
            
    @sp.entry_point
    def unpause(self, token_ids):
        """Allows to unpause tokens, only a token administrator can do this"""
        sp.set_type(token_ids, sp.TList(sp.TNat))
        with sp.for_('token_id', token_ids) as token_id:
            administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            token_context = self.data.token_context[token_id]
            token_context.is_paused = False
            self.data.token_context[token_id] = token_context
                
    @sp.entry_point
    def set_rules(self, rules):
        """Allows to specify the rules contract for a specific token, only a token administrator can do this"""
        sp.set_type(rules, Rule.get_batch_type())
        with sp.for_('rule', rules) as rule:
            administrator_ledger_key = LedgerKey.make(rule.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            self.data.token_context[rule.token_id].can_transfer_rule_contract = rule.rule_contract
    
    @sp.entry_point
    def schedule_snapshot(self, token_id, snapshot_timestamp):
        administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
        sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        sp.verify(sp.now < snapshot_timestamp, message=CMTAFA2ErrorMessage.SNAPSHOT_IN_PAST)
        self.data.token_context[token_id].next_snapshot = sp.some(snapshot_timestamp)

    @sp.entry_point
    def unschedule_snapshot(self, token_id):
        administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
        sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        self.data.token_context[token_id].next_snapshot = sp.none

    # Owner entrypoints
    # --- END ---
    
    # Open Entrypoints
    @sp.entry_point
    def set_identity(self, identity):
        """Allows a user to set the own identity"""
        sp.set_type(identity, sp.TBytes)
        self.data.identities[sp.sender] = identity
    
    @sp.entry_point
    def transfer(self, transfers):
        """Sligthly adapted FA2 transfer method which includes pause, rule engine and snapshot functionality"""
        sp.set_type(transfers, Transfer.get_batch_type())
        with sp.for_('transfer',  transfers) as transfer:
           with sp.for_('tx', transfer.txs) as tx:
                from_user = LedgerKey.make(tx.token_id, transfer.from_)
                to_user = LedgerKey.make(tx.token_id, tx.to_)
                operator_key = OperatorKey.make(tx.token_id, transfer.from_, sp.sender)
                token_context = sp.local("token_context", self.data.token_context[tx.token_id])
                can_transfer_contract = sp.contract(Transfer.get_type(), token_context.value.can_transfer_rule_contract, entry_point="can_transfer")
                with sp.if_(can_transfer_contract.is_some()):
                    sp.transfer(transfer, sp.mutez(0), can_transfer_contract.open_some())
                sp.verify(((transfer.from_ == sp.sender) | self.data.operators.get(operator_key, False)), message = FA2ErrorMessage.NOT_OWNER) # allows of meta transfers
                sp.verify(self.data.token_metadata.contains(tx.token_id), message = FA2ErrorMessage.TOKEN_UNDEFINED)
                sp.verify(~token_context.value.is_paused, message = CMTAFA2ErrorMessage.TOKEN_PAUSED)
                with sp.if_((tx.amount > sp.nat(0))):                    
                    
                    sp.verify((self.data.ledger[from_user] >= tx.amount), message = FA2ErrorMessage.INSUFFICIENT_BALANCE)
                    
                    with sp.if_(token_context.value.next_snapshot.is_some()):
                        with sp.if_(token_context.value.next_snapshot.open_some() < sp.now):
                            with sp.if_(token_context.value.current_snapshot.is_some()):
                                snapshot_lookup_key = SnapshotLookupKey.make(tx.token_id, token_context.value.current_snapshot.open_some())
                                self.data.snapshot_lookup[snapshot_lookup_key] = token_context.value.next_snapshot.open_some()
                            token_context.value.current_snapshot = token_context.value.next_snapshot
                            self.data.token_context[tx.token_id] = token_context.value
                    
                    with sp.if_(token_context.value.current_snapshot.is_some()):
                        from_snapshot_ledger_key = SnapshotLedgerKey.make(tx.token_id, transfer.from_, token_context.value.current_snapshot.open_some())
                        to_snapshot_ledger_key = SnapshotLedgerKey.make(tx.token_id, tx.to_, token_context.value.current_snapshot.open_some())
                        with sp.if_(~self.data.snapshot_ledger.contains(from_snapshot_ledger_key)):
                            self.data.snapshot_ledger[from_snapshot_ledger_key] = self.data.ledger[from_user]
                        with sp.if_(~self.data.snapshot_ledger.contains(to_snapshot_ledger_key)):
                            self.data.snapshot_ledger[to_snapshot_ledger_key] = self.data.ledger.get(to_user, 0)
                    
                    self.data.ledger[from_user] = sp.as_nat(self.data.ledger[from_user] - tx.amount)
                    self.data.ledger[to_user] = self.data.ledger.get(to_user, 0) + tx.amount
                                            
                    with sp.if_(self.data.ledger[from_user] == 0):
                        del self.data.ledger[from_user]
    
    @sp.onchain_view()
    def view_snapshot_balance_of(self, snapshot_ledger_key):
        sp.set_type(snapshot_ledger_key, SnapshotLedgerKey.get_type())
        with sp.if_(self.data.snapshot_ledger.contains(snapshot_ledger_key)):
            sp.result(self.data.snapshot_ledger[snapshot_ledger_key])
        with sp.else_():
            current_snapshot = sp.local("current_snapshot", SnapshotLookupKey.make(snapshot_ledger_key.token_id, snapshot_ledger_key.snapshot_timestamp))    
            current_snapshot_ledger_key = sp.local("current_snapshot_ledger_key", SnapshotLedgerKey.make(snapshot_ledger_key.token_id, snapshot_ledger_key.owner, current_snapshot.value.snapshot_timestamp))
            with sp.if_(self.data.snapshot_lookup.contains(current_snapshot.value)):
                with sp.while_(self.data.snapshot_lookup.contains(current_snapshot.value)):
                    current_snapshot.value = SnapshotLookupKey.make(snapshot_ledger_key.token_id, self.data.snapshot_lookup[current_snapshot.value])
                    current_snapshot_ledger_key.value = SnapshotLedgerKey.make(snapshot_ledger_key.token_id, snapshot_ledger_key.owner, current_snapshot.value.snapshot_timestamp)
                with sp.if_(self.data.snapshot_ledger.contains(current_snapshot_ledger_key.value)):
                    sp.result(self.data.snapshot_ledger[current_snapshot_ledger_key.value])
                with sp.else_():
                    sp.result(self.data.ledger[LedgerKey.make(snapshot_ledger_key.token_id, snapshot_ledger_key.owner)])
            with sp.else_():
                sp.result(self.data.ledger[LedgerKey.make(snapshot_ledger_key.token_id, snapshot_ledger_key.owner)])



class AllowListRuleEngine(sp.Contract):
    def __init__(self):
        self.init(allow_list=sp.big_map(tkey=sp.TAddress, tvalue=sp.TBool))
        
    @sp.entry_point
    def add(self, address):
        sp.set_type_expr(address, sp.TAddress)
        self.data.allow_list[address] = True

    @sp.entry_point
    def can_transfer(self, transfer):
        sp.set_type(transfer, Transfer.get_type())
        with sp.for_('tx', transfer.txs) as tx:
            sp.verify(self.data.allow_list.contains(transfer.from_), message=CMTAFA2ErrorMessage.CANNOT_TRANSFER)
            sp.verify(self.data.allow_list.contains(tx.to_), message=CMTAFA2ErrorMessage.CANNOT_TRANSFER)