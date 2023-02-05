"""
# CMTA FA2 Blueprint Implementation

Checkout `readme.md` for documenation.

"""
import smartpy as sp

from contracts.fa2 import AdministrableFA2, FA2ErrorMessage, AdministratorState, LedgerKey, AdministrableErrorMessage, TokenMetadata, OperatorKey, Transfer

NULL_ADDRESS = sp.address("tz1YtuZ4vhzzn7ssCt93Put8U9UJDdvCXci4")
NULL_BYTES = sp.bytes('0x')
   
class TokenAmount:
    def get_type():
        return sp.TRecord(token_id = sp.TNat, amount = sp.TNat, address = sp.TAddress).layout(("token_id", ("amount", "address")))
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

class TokenContext:
    def get_type():
        return sp.TRecord(is_paused=sp.TBool, validate_transfer_rule_contract=sp.TOption(sp.TAddress), current_snapshot=sp.TOption(sp.TTimestamp), next_snapshot=sp.TOption(sp.TTimestamp))

class ValidationTransfer:
    def get_type():
        return sp.TRecord(from_=sp.TAddress, to_=sp.TAddress, token_id=sp.TNat, amount=sp.TNat).layout(("from_", ("to_", ("token_id", "amount"))))
    
    def make(from_, to_, token_id, amount):
        """Creates a typed ledger key"""
        return sp.set_type_expr(sp.record(from_ = from_, to_ = to_,  token_id = token_id, amount = amount), ValidationTransfer.get_type())

class CMTAFA2ErrorMessage:
    """Static enum used for the FA2 related errors, using the `FA2_` prefix"""
    PREFIX = "CM_"
    TOKEN_PAUSED = "{}TOKEN_PAUSED".format(PREFIX)
    TOKEN_EXISTS = "{}TOKEN_EXISTS".format(PREFIX)
    SAME_REASSIGN = "{}SAME_REASSIGN".format(PREFIX)
    CANNOT_TRANSFER = "{}CANNOT_TRANSFER".format(PREFIX)
    SNAPSHOT_IN_PAST = "{}SNAPSHOT_IN_PAST".format(PREFIX)
    SNAPSHOT_ONGOING = "{}SNAPSHOT_ONGOING".format(PREFIX)
    SNAPSHOT_ALREADY_SCHEDULED = "{}ALREADY_SCHEDULED".format(PREFIX)
    INVALID_RULE = "{}INVALID_RULE".format(PREFIX)
        
class CMTAFA2(AdministrableFA2):
    """FA2 Contract blueprint for CMTA tokens""" 
    def get_init_storage(self):
        """Returns the initial storage of the contract"""
        storage = super().get_init_storage()
        storage['snapshot_ledger'] = sp.big_map(tkey=SnapshotLedgerKey.get_type(), tvalue=sp.TNat)
        storage['snapshot_lookup'] = sp.big_map(tkey=SnapshotLookupKey.get_type(), tvalue=sp.TTimestamp)
        storage['snapshot_total_supply'] = sp.big_map(tkey=SnapshotLookupKey.get_type(), tvalue=sp.TNat)
        storage['token_context'] = sp.big_map(tkey=sp.TNat, tvalue=TokenContext.get_type())
        storage['identities'] = sp.big_map(tkey=sp.TAddress, tvalue=sp.TBytes)
        return storage
        
    def __init__(self, administrators):
        super().__init__(administrators)

    # Helper lambdas
    @sp.private_lambda(with_operations=False, with_storage="read-write", wrap_call=True)
    def bootstrap_snapshot(self, params):
        sp.set_type_expr(params, sp.TPair(TokenContext.get_type(), sp.TNat))
        raw_token_context, token_id = sp.match_pair(params)
        
        token_context=  sp.local("token_context", raw_token_context)

        with sp.if_(token_context.value.next_snapshot.is_some()):
            with sp.if_(token_context.value.next_snapshot.open_some() < sp.now):
                with sp.if_(token_context.value.current_snapshot.is_some()):
                    snapshot_lookup_key = SnapshotLookupKey.make(token_id, token_context.value.current_snapshot.open_some())
                    self.data.snapshot_lookup[snapshot_lookup_key] = token_context.value.next_snapshot.open_some()
                token_context.value.current_snapshot = token_context.value.next_snapshot
                token_context.value.next_snapshot = sp.none
                self.data.token_context[token_id] = token_context.value
    
    @sp.private_lambda(with_operations=False, with_storage="read-write", wrap_call=True)
    def set_snapshot_ledger(self, params):
        sp.set_type_expr(params, sp.TTuple(TokenContext.get_type(), sp.TNat, sp.TAddress))
        token_context, token_id, address = sp.match_tuple(params, "token_context", "token_id", "address")

        with sp.if_(token_context.current_snapshot.is_some()):
            snapshot_ledger_key = sp.local("snapshot_ledger_key", SnapshotLedgerKey.make(token_id, address, token_context.current_snapshot.open_some()))
            with sp.if_(~self.data.snapshot_ledger.contains(snapshot_ledger_key.value)):
                self.data.snapshot_ledger[snapshot_ledger_key.value] = self.data.ledger.get(LedgerKey.make(token_id, address), 0)

    @sp.private_lambda(with_operations=False, with_storage="read-write", wrap_call=True)
    def set_snapshot_total_supply(self, params):
        sp.set_type_expr(params, sp.TPair(TokenContext.get_type(), sp.TNat))
        token_context, token_id = sp.match_pair(params)

        with sp.if_(token_context.current_snapshot.is_some()):
            snapshot_lookup_key = sp.local("snapshot_lookup_key", SnapshotLookupKey.make(token_id, token_context.current_snapshot.open_some()))
            with sp.if_(~self.data.snapshot_total_supply.contains(snapshot_lookup_key.value)):
                self.data.snapshot_total_supply[snapshot_lookup_key.value] = self.data.total_supply.get(token_id, 0)
    # Owner entry points 
    # --- START ---
    @sp.entry_point
    def initialise_token(self, token_ids):
        """Initialise the token with the required additional token context, can only be called once per token and only one of its admin can call this"""
        sp.set_type_expr(token_ids, sp.TList(sp.TNat))

        with sp.for_('token_id', token_ids) as token_id:
            sp.verify((~self.data.token_context.contains(token_id)), message = CMTAFA2ErrorMessage.TOKEN_EXISTS)            
            administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            self.data.token_context[token_id] = sp.record(is_paused=False, validate_transfer_rule_contract=sp.none, current_snapshot=sp.none, next_snapshot=sp.none)
        
    @sp.entry_point
    def mint(self, token_amounts):
        """Allows to mint new tokens to the defined recipient address, only a token administrator can do this"""
        sp.set_type(token_amounts, TokenAmount.get_batch_type())
        with sp.for_('token_amount', token_amounts) as token_amount:
            administrator_ledger_key = LedgerKey.make(token_amount.token_id, sp.sender)
            recipient_ledger_key = sp.local("recipient_ledger_key", LedgerKey.make(token_amount.token_id, token_amount.address))
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            sp.verify(self.data.token_metadata.contains(token_amount.token_id), message = FA2ErrorMessage.TOKEN_UNDEFINED)
            
            token_context = sp.local("token_context", self.data.token_context[token_amount.token_id])
            
            self.bootstrap_snapshot(sp.pair(token_context.value, token_amount.token_id))
            token_context.value = self.data.token_context[token_amount.token_id]
            
            self.set_snapshot_total_supply(sp.pair(token_context.value, token_amount.token_id))
            self.set_snapshot_ledger((token_context.value, token_amount.token_id, token_amount.address))
            
            self.data.ledger[recipient_ledger_key.value] = self.data.ledger.get(recipient_ledger_key.value, 0) + token_amount.amount
            self.data.total_supply[token_amount.token_id] = self.data.total_supply.get(token_amount.token_id, 0) + token_amount.amount

                   
    @sp.entry_point
    def burn(self, token_amounts):
        """Allows to burn tokens on the defined recipient address, only a token administrator can do this"""
        sp.set_type(token_amounts, TokenAmount.get_batch_type())
        with sp.for_('token_amount', token_amounts) as token_amount:
            administrator_ledger_key = LedgerKey.make(token_amount.token_id, sp.sender)
            recipient_ledger_key = sp.local("recipient_ledger_key", LedgerKey.make(token_amount.token_id, token_amount.address))
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            sp.verify(self.data.ledger[recipient_ledger_key.value]>=token_amount.amount, message = FA2ErrorMessage.INSUFFICIENT_BALANCE)
            
            token_context = sp.local("token_context", self.data.token_context[token_amount.token_id])
            
            self.bootstrap_snapshot(sp.pair(token_context.value, token_amount.token_id))
            token_context.value = self.data.token_context[token_amount.token_id]
            
            self.set_snapshot_total_supply(sp.pair(token_context.value, token_amount.token_id))
            self.set_snapshot_ledger((token_context.value, token_amount.token_id, token_amount.address))
                      
            self.data.ledger[recipient_ledger_key.value] = sp.as_nat(self.data.ledger.get(recipient_ledger_key.value, 0) - token_amount.amount)
            self.data.total_supply[token_amount.token_id] = sp.as_nat(self.data.total_supply.get(token_amount.token_id, 0) - token_amount.amount)
            
            with sp.if_(self.data.ledger[recipient_ledger_key.value] == 0):
                del self.data.ledger[recipient_ledger_key.value]
                
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
    def set_rule_engines(self, rules):
        """Allows to specify the rules contract for a specific token, only a token administrator can do this"""
        sp.set_type(rules, Rule.get_batch_type())
        with sp.for_('rule', rules) as rule:
            administrator_ledger_key = LedgerKey.make(rule.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            self.data.token_context[rule.token_id].validate_transfer_rule_contract = sp.some(rule.rule_contract)
    
    @sp.entry_point
    def schedule_snapshot(self, token_id, snapshot_timestamp):
        """Schedules a snapshot for the future for a specific token. Only one snapshot can be scheduled, repeated call will fail, to re-schedule you need to unschedule using the `unschedule_snapshot` entry point first. Only token administrator can do this."""
        administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
        sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        sp.verify(self.data.token_context[token_id].next_snapshot.is_none(), message=CMTAFA2ErrorMessage.SNAPSHOT_ALREADY_SCHEDULED)
        sp.verify(sp.now < snapshot_timestamp, message=CMTAFA2ErrorMessage.SNAPSHOT_IN_PAST)
        self.data.token_context[token_id].next_snapshot = sp.some(snapshot_timestamp)

    @sp.entry_point
    def unschedule_snapshot(self, token_id):
        """Unschedules the scheduled snapshot for the given token_id. Only token administrator can do this.""" 
        administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
        sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        self.data.token_context[token_id].next_snapshot = sp.none
    
    @sp.entry_point
    def delete_snapshot(self, snapshot_lookup_key):
        """Deletes a snapshot for the given snapshot lookup key (consisting of token_id = sp.TNat, snapshot_timestamp = sp.TTimestamp). Only token administrator can do this.""" 
        sp.set_type(snapshot_lookup_key, SnapshotLookupKey.get_type())
        administrator_ledger_key = LedgerKey.make(snapshot_lookup_key.token_id, sp.sender)
        sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        del self.data.snapshot_lookup[snapshot_lookup_key]

    @sp.entry_point
    def kill(self):
        """Wipes irreversibly the storage and ultimately kills the contract such that it can no longer be used. All tokens on it will be affected. Only special admin of token id 0 can do this."""
        administrator_ledger_key = LedgerKey.make(sp.nat(0), sp.sender)
        sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        self.data.ledger = sp.big_map(tkey=LedgerKey.get_type(), tvalue=sp.TNat)
        self.data.administrators = sp.big_map(tkey=LedgerKey.get_type(), tvalue = sp.TNat)
        self.data.token_metadata = sp.big_map(tkey=sp.TNat, tvalue = TokenMetadata.get_type())
        self.data.total_supply = sp.big_map(tkey=sp.TNat, tvalue = sp.TNat)
        self.data.operators = sp.big_map(tkey=OperatorKey.get_type(), tvalue = sp.TUnit)
        self.data.token_context = sp.big_map(tkey=sp.TNat, tvalue=sp.TRecord(is_paused=sp.TBool, validate_transfer_rule_contract=sp.TOption(sp.TAddress), current_snapshot=sp.TOption(sp.TTimestamp), next_snapshot=sp.TOption(sp.TTimestamp)))
        self.data.identities = sp.big_map(tkey=sp.TAddress, tvalue=sp.TBytes)
    # Owner entry points
    # --- END ---
    
    # Open entry points
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
                from_user = sp.local("from_user", LedgerKey.make(tx.token_id, transfer.from_))
                to_user = sp.local("to_user", LedgerKey.make(tx.token_id, tx.to_))
                operator_key = OperatorKey.make(tx.token_id, transfer.from_, sp.sender)
                token_context = sp.local("token_context", self.data.token_context[tx.token_id])
                with sp.if_(token_context.value.validate_transfer_rule_contract.is_some()):
                    is_transfer_valid = sp.view("view_is_transfer_valid", token_context.value.validate_transfer_rule_contract.open_some(CMTAFA2ErrorMessage.INVALID_RULE), ValidationTransfer.make(transfer.from_, tx.to_, tx.token_id, tx.amount), t = sp.TBool).open_some(CMTAFA2ErrorMessage.INVALID_RULE)
                    sp.verify(is_transfer_valid, message=CMTAFA2ErrorMessage.CANNOT_TRANSFER)       
                sp.verify(((transfer.from_ == sp.sender) | self.data.operators.contains(operator_key)), message = FA2ErrorMessage.NOT_OPERATOR) # allows of meta transfers
                sp.verify(self.data.token_metadata.contains(tx.token_id), message = FA2ErrorMessage.TOKEN_UNDEFINED)
                sp.verify(~token_context.value.is_paused, message = CMTAFA2ErrorMessage.TOKEN_PAUSED)
                with sp.if_((tx.amount > sp.nat(0))):                    
                    
                    sp.verify((self.data.ledger[from_user.value] >= tx.amount), message = FA2ErrorMessage.INSUFFICIENT_BALANCE)
                    
                    self.bootstrap_snapshot(sp.pair(token_context.value, tx.token_id))
                    token_context.value = self.data.token_context[tx.token_id]
            
                    self.set_snapshot_ledger((token_context.value, tx.token_id, tx.to_))
                    self.set_snapshot_ledger((token_context.value, tx.token_id, transfer.from_))
                    
                    with sp.if_(tx.amount >= sp.nat(0)):
                        self.data.ledger[from_user.value] = sp.as_nat(self.data.ledger[from_user.value] - tx.amount)
                        self.data.ledger[to_user.value] = self.data.ledger.get(to_user.value, 0) + tx.amount
                                            
                    with sp.if_(self.data.ledger[from_user.value] == 0):
                        del self.data.ledger[from_user.value]
    
    @sp.onchain_view()
    def view_total_supply(self, token_id):
        """Given a token id allows the consumer to view the current total supply."""
        sp.set_type(token_id, sp.TNat)
        sp.result(self.data.total_supply.get(token_id,0))    
    
    @sp.onchain_view()
    def view_balance_of(self, ledger_key):
        """Given a ledger key (consisting of token_id = sp.TNat, owner = sp.TAddress) allows the consumer to view the current balance."""
        sp.set_type(ledger_key, LedgerKey.get_type())
        sp.result(self.data.ledger.get(ledger_key,0))    
    
    @sp.onchain_view()
    def view_current_snapshot(self, token_id):
        """Given a token id allows the consumer to view the current snapshot timestamp. Can be null."""
        sp.set_type(token_id, sp.TNat)
        sp.result(self.data.token_context[token_id].current_snapshot)    
    
    @sp.onchain_view()
    def view_next_snapshot(self, token_id):
        """Given a token id allows the consumer to view the next snapshot timestamp. Can be null."""
        sp.set_type(token_id, sp.TNat)
        sp.result(self.data.token_context[token_id].next_snapshot)

    @sp.onchain_view()
    def view_snapshot_total_supply(self, snapshot_lookup_key):
        """Given the snapshot lookup key (consisting of token_id = sp.TNat, snapshot_timestamp = sp.TTimestamp) allows the consumer to retrieve the total supply in nat of a given snapshot."""
        sp.set_type(snapshot_lookup_key, SnapshotLookupKey.get_type())
        with sp.if_(self.data.snapshot_total_supply.contains(snapshot_lookup_key)):
            sp.result(self.data.snapshot_total_supply[snapshot_lookup_key])
        with sp.else_():
            keep_loop = sp.local("keep_loop", True)
            current_snapshot_lookup_key = sp.local("current_snapshot_lookup_key", snapshot_lookup_key)    
            with sp.while_(keep_loop.value):
                with sp.if_(self.data.snapshot_lookup.contains(current_snapshot_lookup_key.value)):
                    current_snapshot_lookup_key.value = SnapshotLookupKey.make(snapshot_lookup_key.token_id, self.data.snapshot_lookup[current_snapshot_lookup_key.value])
                    with sp.if_(self.data.snapshot_total_supply.contains(current_snapshot_lookup_key.value)):
                        keep_loop.value = False
                with sp.else_():
                    keep_loop.value = False
            with sp.if_(self.data.snapshot_total_supply.contains(current_snapshot_lookup_key.value)):
                sp.result(self.data.snapshot_total_supply[current_snapshot_lookup_key.value])
            with sp.else_():
                sp.result(self.data.total_supply.get(snapshot_lookup_key.token_id, 0))

    @sp.onchain_view()
    def view_snapshot_balance_of(self, snapshot_ledger_key):
        """Given the snapshot ledger key (consisting of token_id = sp.TNat, owner = sp.TAddress, snapshot_timestamp = sp.TTimestamp) allows the consumer to retrieve the balance in nat of a given snapshot."""   
        sp.set_type(snapshot_ledger_key, SnapshotLedgerKey.get_type())
        with sp.if_(self.data.snapshot_ledger.contains(snapshot_ledger_key)):
            sp.result(self.data.snapshot_ledger[snapshot_ledger_key])
        with sp.else_():
            keep_loop = sp.local("keep_loop", True)
            current_snapshot_lookup_key = sp.local("current_snapshot_lookup_key", SnapshotLookupKey.make(snapshot_ledger_key.token_id, snapshot_ledger_key.snapshot_timestamp))    
            current_snapshot_ledger_key = sp.local("current_snapshot_ledger_key", SnapshotLedgerKey.make(snapshot_ledger_key.token_id, snapshot_ledger_key.owner, current_snapshot_lookup_key.value.snapshot_timestamp))
            with sp.while_(keep_loop.value):
                with sp.if_(self.data.snapshot_lookup.contains(current_snapshot_lookup_key.value)):
                    current_snapshot_lookup_key.value = SnapshotLookupKey.make(snapshot_ledger_key.token_id, self.data.snapshot_lookup[current_snapshot_lookup_key.value])
                    current_snapshot_ledger_key.value = SnapshotLedgerKey.make(snapshot_ledger_key.token_id, snapshot_ledger_key.owner, current_snapshot_lookup_key.value.snapshot_timestamp)
                    with sp.if_(self.data.snapshot_ledger.contains(current_snapshot_ledger_key.value)):
                        keep_loop.value = False
                with sp.else_():
                    keep_loop.value = False
            with sp.if_(self.data.snapshot_ledger.contains(current_snapshot_ledger_key.value)):
                sp.result(self.data.snapshot_ledger[current_snapshot_ledger_key.value])
            with sp.else_():
                sp.result(self.data.ledger.get(LedgerKey.make(snapshot_ledger_key.token_id, snapshot_ledger_key.owner), 0))




