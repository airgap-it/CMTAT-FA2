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
        sp.for transfer in transfers:
            sp.for tx in transfer.txs:
                from_user = LedgerKey.make(tx.token_id, transfer.from_)
                to_user = LedgerKey.make(tx.token_id, tx.to_)
                operator_key = OperatorKey.make(tx.token_id, transfer.from_, sp.sender)

                sp.verify(self.data.ledger.get(from_user,sp.nat(0)) >= tx.amount, message = FA2ErrorMessage.INSUFFICIENT_BALANCE)                                     
                sp.verify((sp.sender == transfer.from_) | self.data.operators.get(operator_key, False), message=FA2ErrorMessage.NOT_OWNER)
                
                self.data.ledger[from_user] = sp.as_nat(self.data.ledger[from_user] - tx.amount)
                self.data.ledger[to_user] = self.data.ledger.get(to_user, 0) + tx.amount
                
                sp.if sp.sender != transfer.from_:
                    del self.data.operators[operator_key]
                    
                sp.if self.data.ledger.get(from_user,sp.nat(0)) == sp.nat(0):
                    del self.data.ledger[from_user]

    @sp.entry_point
    def update_operators(self, update_operators):
        """As per FA2 standard, allows a token owner to set an operator who will be allowed to perform transfers on her/his behalf"""
        sp.set_type(update_operators,UpdateOperator.get_batch_type())
        sp.for update_operator in update_operators:
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
        sp.for request in balance_of_request.requests:
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
        sp.for token_metadata in token_metadata_list:
            administrator_ledger_key = LedgerKey.make(token_metadata.token_id, sp.sender)
            sp.if self.data.token_metadata.contains(token_metadata.token_id):
                sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            sp.else:
                sp.if sp.len(self.data.administrator_allowmap)>0:    
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
                              

class CMTAFA2ErrorMessage:
    """Static enum used for the FA2 related errors, using the `FA2_` prefix"""
    PREFIX = "CM_"
    TOKEN_PAUSED = "{}TOKEN_PAUSED".format(PREFIX)
    TOKEN_EXISTS = "{}TOKEN_EXISTS".format(PREFIX)
    SAME_REASSIGN = "{}SAME_REASSIGN".format(PREFIX)
    CANNOT_TRANSFER = "{}CANNOT_TRANSFER".format(PREFIX)
        
class CMTAFA2(AdministrableFA2):
    """FA2 Contract blueprint for CMTA tokens""" 
    def get_init_storage(self):
        """Returns the initial storage of the contract"""
        storage = super().get_init_storage()
        storage['token_context'] = sp.big_map(tkey=sp.TNat, tvalue=sp.TRecord(contact=sp.TBytes, is_paused=sp.TBool, can_transfer_rule_contract=sp.TAddress))
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

        sp.for token_id in token_ids:
            sp.verify((~self.data.token_context.contains(token_id)), message = CMTAFA2ErrorMessage.TOKEN_EXISTS)            
            administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            self.data.token_context[token_id] = sp.record(contact=NULL_BYTES, is_paused=False, can_transfer_rule_contract=NULL_ADDRESS)
        
    @sp.entry_point
    def set_contacts(self, contacts):
        """Allows to set the contact of multiple tokens, only token a administrator can do this"""
        sp.set_type_expr(contacts, Contact.get_batch_type())
        sp.for contact in contacts:
            token_context = self.data.token_context[contact.token_id]
            administrator_ledger_key = LedgerKey.make(contact.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            token_context.contact = contact.contact
            self.data.token_context[contact.token_id] = token_context

    @sp.entry_point
    def issue(self, token_amounts):
        """Allows to issue new tokens to the calling admin's address, only a token administrator can do this"""
        sp.set_type(token_amounts, TokenAmount.get_batch_type())
        sp.for token_amount in token_amounts:
            administrator_ledger_key = LedgerKey.make(token_amount.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            sp.verify(self.data.token_metadata.contains(token_amount.token_id), message = FA2ErrorMessage.TOKEN_UNDEFINED)
            self.data.ledger[administrator_ledger_key] = self.data.ledger.get(administrator_ledger_key, 0) + token_amount.amount
            self.data.total_supply[token_amount.token_id] = self.data.total_supply.get(token_amount.token_id, 0) + token_amount.amount
    
    @sp.entry_point
    def redeem(self, token_amounts):
        """Allows to redeem tokens on the calling admin's address, only a token administrator can do this"""
        sp.set_type(token_amounts, TokenAmount.get_batch_type())
        sp.for token_amount in token_amounts:
            administrator_ledger_key = LedgerKey.make(token_amount.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            sp.verify(self.data.ledger[administrator_ledger_key]>=token_amount.amount, message = FA2ErrorMessage.INSUFFICIENT_BALANCE)
            self.data.ledger[administrator_ledger_key] = sp.as_nat(self.data.ledger.get(administrator_ledger_key, 0) - token_amount.amount)
            self.data.total_supply[token_amount.token_id] = sp.as_nat(self.data.total_supply.get(token_amount.token_id, 0) - token_amount.amount)
            
            sp.if self.data.ledger[administrator_ledger_key] == 0:
                del self.data.ledger[administrator_ledger_key]
    
    @sp.entry_point
    def reassign(self, reassignments):
        """Allows to reassing tokens on the calling admin's address, only a token administrator can do this"""
        sp.set_type(reassignments, Reassignment.get_batch_type())
        sp.for reassignment in reassignments:
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
        sp.for destruction in destructions:
            administrator_ledger_key = LedgerKey.make(destruction.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            sp.for holder in destruction.holders:
                holder_ledger_key = LedgerKey.make(destruction.token_id, holder)
                sp.verify(self.data.ledger[holder_ledger_key]>sp.nat(0), message = FA2ErrorMessage.INSUFFICIENT_BALANCE)
                self.data.ledger[administrator_ledger_key] = self.data.ledger[holder_ledger_key]
                del self.data.ledger[holder_ledger_key]
                
    @sp.entry_point
    def pause(self, token_ids):
        """Allows to pause tokens, only a token administrator can do this"""
        sp.set_type(token_ids, sp.TList(sp.TNat))
        sp.for token_id in token_ids:
            administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            token_context = self.data.token_context[token_id]
            token_context.is_paused = True
            self.data.token_context[token_id] = token_context
            
    @sp.entry_point
    def unpause(self, token_ids):
        """Allows to unpause tokens, only a token administrator can do this"""
        sp.set_type(token_ids, sp.TList(sp.TNat))
        sp.for token_id in token_ids:
            administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            token_context = self.data.token_context[token_id]
            token_context.is_paused = False
            self.data.token_context[token_id] = token_context
                
    @sp.entry_point
    def set_rules(self, rules):
        """Allows to specify the rules contract for a specific token, only a token administrator can do this"""
        sp.set_type(rules, Rule.get_batch_type())
        sp.for rule in rules:
            administrator_ledger_key = LedgerKey.make(rule.token_id, sp.sender)
            sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
            self.data.token_context[rule.token_id].can_transfer_rule_contract = rule.rule_contract
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
        """Sligthly adapted FA2 transfer method which includes pause and rule engine functionality"""
        sp.set_type(transfers, Transfer.get_batch_type())
        sp.for transfer in  transfers:
           sp.for tx in transfer.txs:
                token_context = self.data.token_context[tx.token_id]
                can_transfer_contract = sp.contract(Transfer.get_type(), token_context.can_transfer_rule_contract, entry_point="can_transfer")
                sp.if can_transfer_contract.is_some():
                    sp.transfer(transfer, sp.mutez(0), can_transfer_contract.open_some())
                sp.verify((transfer.from_ == sp.sender), message = FA2ErrorMessage.NOT_OWNER)
                sp.verify(self.data.token_metadata.contains(tx.token_id), message = FA2ErrorMessage.TOKEN_UNDEFINED)
                sp.verify(~token_context.is_paused, message = CMTAFA2ErrorMessage.TOKEN_PAUSED)
                token_context
                # TODO rule
                sp.if (tx.amount > sp.nat(0)):
                    from_user = LedgerKey.make(tx.token_id, transfer.from_)
                    to_user = LedgerKey.make(tx.token_id, tx.to_)
                    sp.verify((self.data.ledger[from_user] >= tx.amount), message = FA2ErrorMessage.INSUFFICIENT_BALANCE)
                    self.data.ledger[from_user] = sp.as_nat(self.data.ledger[from_user] - tx.amount)
                    self.data.ledger[to_user] = self.data.ledger.get(to_user, 0) + tx.amount

                    sp.if self.data.ledger[from_user] == 0:
                        del self.data.ledger[from_user]


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
        sp.for tx in transfer.txs:
            sp.verify(self.data.allow_list.contains(transfer.from_), message=CMTAFA2ErrorMessage.CANNOT_TRANSFER)
            sp.verify(self.data.allow_list.contains(tx.to_), message=CMTAFA2ErrorMessage.CANNOT_TRANSFER)
        
@sp.add_test(name="CMTA20 Blueprint")
def test():
    scenario = sp.test_scenario()
    scenario.h1("CMTAFA2 - A blueprint CMTAFA2 implementation")
    scenario.table_of_contents()

    administrator = sp.test_account("Adiministrator")
    alice = sp.test_account("Alice")
    bob = sp.test_account("Robert")
    dan = sp.test_account("Dan")


    scenario.h2("Accounts")
    scenario.show([administrator, alice, bob, dan])
    cmta_fa2_contract = CMTAFA2({administrator.address:True})
    scenario += cmta_fa2_contract
    
    scenario.h2("Admin Calls")
    scenario.h3("Initialise 3 tokens")
    token_metadata_list = [sp.record(token_id=sp.nat(0), token_metadata=sp.map()),sp.record(token_id=sp.nat(1), token_metadata=sp.map()),sp.record(token_id=sp.nat(2), token_metadata=sp.map())]
    scenario += cmta_fa2_contract.set_token_metadata(token_metadata_list).run(sender=administrator)
    scenario += cmta_fa2_contract.initialise_token([sp.nat(0),sp.nat(1),sp.nat(2)]).run(sender=administrator)
    
    
    scenario.h2("Owner Only Calls")
    scenario.h3("Transferring the Ownership to the individual owners")
    ownerships = [sp.record(token_id=sp.nat(0), owner=alice.address),sp.record(token_id=sp.nat(1), proposed_administrator=bob.address),sp.record(token_id=sp.nat(2), owner=dan.address)]
    
    scenario.p("Not admin trying to propose new owner")
    scenario += cmta_fa2_contract.propose_administrator(sp.record(token_id=sp.nat(0), proposed_administrator=alice.address)).run(sender=alice, valid=False)
    
    scenario.p("Not admin trying to transfer directly")
    scenario += cmta_fa2_contract.set_administrator(sp.nat(0)).run(sender=bob, valid=False)
    
    scenario.p("Correct admin trying to transfer directly")
    scenario += cmta_fa2_contract.set_administrator(sp.nat(0)).run(sender=administrator, valid=False)
    
    scenario.p("Correct admin trying to propose transfer")
    scenario += cmta_fa2_contract.propose_administrator(sp.record(token_id=sp.nat(0), proposed_administrator=alice.address)).run(sender=administrator, valid=True)
    scenario += cmta_fa2_contract.propose_administrator(sp.record(token_id=sp.nat(1), proposed_administrator=bob.address)).run(sender=administrator, valid=True)
    scenario += cmta_fa2_contract.propose_administrator(sp.record(token_id=sp.nat(2), proposed_administrator=dan.address)).run(sender=administrator, valid=True)
    
    scenario.p("Correct admin (but not proposed) trying to transfer")
    scenario += cmta_fa2_contract.set_administrator(sp.nat(0)).run(sender=administrator, valid=False)    
    
    scenario.p("Proposed admin trying to transfer")
    scenario += cmta_fa2_contract.set_administrator(sp.nat(0)).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.set_administrator(sp.nat(1)).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.set_administrator(sp.nat(2)).run(sender=dan, valid=True)
    
    scenario.p("Non Admin deletes rights")
    scenario += cmta_fa2_contract.remove_administrator(sp.record(token_id=sp.nat(0), administrator_to_remove=administrator.address)).run(sender=dan, valid=False)
    scenario += cmta_fa2_contract.remove_administrator(sp.record(token_id=sp.nat(1), administrator_to_remove=administrator.address)).run(sender=alice, valid=False)
    scenario += cmta_fa2_contract.remove_administrator(sp.record(token_id=sp.nat(2), administrator_to_remove=administrator.address)).run(sender=bob, valid=False)
    
    scenario.p("Admin deletes own rights")
    scenario += cmta_fa2_contract.remove_administrator(sp.record(token_id=sp.nat(0), administrator_to_remove=administrator.address)).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.remove_administrator(sp.record(token_id=sp.nat(1), administrator_to_remove=administrator.address)).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.remove_administrator(sp.record(token_id=sp.nat(2), administrator_to_remove=administrator.address)).run(sender=dan, valid=True)
   
    scenario.h3("Setting the Contact")
    scenario.p("Correct admin but not owner trying to set contact")
    scenario += cmta_fa2_contract.set_contacts([sp.record(token_id=sp.nat(0), contact=sp.bytes_of_string("contact@papers.ch"))]).run(sender=administrator, valid=False)
    
    scenario.p("Incorrect owner trying to set contact (Alice is owner of 0 not 1)")
    scenario += cmta_fa2_contract.set_contacts([sp.record(token_id=sp.nat(1), contact=sp.bytes_of_string("contact@papers.ch"))]).run(sender=alice, valid=False)
    
    scenario.p("Correct owner trying to batch set contact (Alice is owner of 0 not 1 and 2)")
    scenario += cmta_fa2_contract.set_contacts([sp.record(token_id=sp.nat(0), contact=sp.bytes_of_string("alice@papers.ch")), sp.record(token_id=sp.nat(1), contact=sp.bytes_of_string("bob@papers.ch")), sp.record(token_id=sp.nat(2), contact=sp.bytes_of_string("dan@papers.ch"))]).run(sender=alice, valid=False)
    
    scenario.p("Correct owners setting contacts")
    scenario += cmta_fa2_contract.set_contacts([sp.record(token_id=sp.nat(0), contact=sp.bytes_of_string("alice@papers.ch"))]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.set_contacts([sp.record(token_id=sp.nat(1), contact=sp.bytes_of_string("bob@papers.ch"))]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.set_contacts([sp.record(token_id=sp.nat(2), contact=sp.bytes_of_string("dan@papers.ch"))]).run(sender=dan, valid=True)
    
    
    scenario.h3("Issuing")
    scenario.p("Correct admin but not owner trying to issue")
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(0), amount=sp.nat(100))]).run(sender=administrator, valid=False)
    
    scenario.p("Incorrect owner trying to issue (Alice is owner of 0 not 1)")
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(1), amount=sp.nat(100))]).run(sender=alice, valid=False)
    
    scenario.p("Correct owner trying to batch issue (Alice is owner of 0 not 1 and 2)")
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(0), amount=sp.nat(100)), sp.record(token_id=sp.nat(1), amount=sp.nat(100)), sp.record(token_id=sp.nat(2), amount=sp.nat(100))]).run(sender=alice, valid=False)
    
    scenario.p("Correct owners issuing tokens")
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(0), amount=sp.nat(100))]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(1), amount=sp.nat(100))]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(2), amount=sp.nat(100))]).run(sender=dan, valid=True)
    
    scenario.p("Correct owners issuing additional amounts of tokens")
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(0), amount=sp.nat(101))]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(1), amount=sp.nat(101))]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(2), amount=sp.nat(101))]).run(sender=dan, valid=True)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(0, alice.address)] == 201)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(1, bob.address)] == 201)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(2, dan.address)] == 201)
    
    scenario.h3("Redemption")
    scenario.p("Correct admin but not owner trying to redeem")
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(0), amount=sp.nat(100))]).run(sender=administrator, valid=False)
    
    scenario.p("Incorrect owner trying to redeem (Alice is owner of 0 not 1)")
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(1), amount=sp.nat(100))]).run(sender=alice, valid=False)
    
    scenario.p("Correct owner trying to batch redeem (Alice is owner of 0 not 1 and 2)")
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(0), amount=sp.nat(100)), sp.record(token_id=sp.nat(1), amount=sp.nat(100)), sp.record(token_id=sp.nat(1), amount=sp.nat(100))]).run(sender=alice, valid=False)
    
    scenario.p("Correct owners redeeming tokens")
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(0), amount=sp.nat(100))]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(1), amount=sp.nat(100))]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(2), amount=sp.nat(100))]).run(sender=dan, valid=True)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(0, alice.address)] == 101)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(1, bob.address)] == 101)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(2, dan.address)] == 101)
    
    scenario.p("Cannot redeem more than owner has")
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(0), amount=sp.nat(201))]).run(sender=alice, valid=False)
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(1), amount=sp.nat(201))]).run(sender=bob, valid=False)
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(2), amount=sp.nat(201))]).run(sender=dan, valid=False)
    
    scenario.p("Correct owners redeeming additional amounts of tokens")
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(0), amount=sp.nat(101))]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(1), amount=sp.nat(101))]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(2), amount=sp.nat(101))]).run(sender=dan, valid=True)
    scenario.verify(~cmta_fa2_contract.data.ledger.contains(LedgerKey.make(0, alice.address)))
    scenario.verify(~cmta_fa2_contract.data.ledger.contains(LedgerKey.make(1, bob.address)))
    scenario.verify(~cmta_fa2_contract.data.ledger.contains(LedgerKey.make(2, dan.address)))
    

    
    scenario.h3("Reassign")
    scenario.p("Bootstrapping by issuing some tokens")
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(0), amount=sp.nat(50))]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(1), amount=sp.nat(47))]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.issue([sp.record(token_id=sp.nat(2), amount=sp.nat(39))]).run(sender=dan, valid=True)
    
    scenario.p("Correct admin but not owner trying to reassign")
    scenario += cmta_fa2_contract.reassign([sp.record(token_id=sp.nat(0), original_holder=alice.address, replacement_holder=alice.address)]).run(sender=administrator, valid=False)
    
    scenario.p("Incorrect owner trying to reassign (Alice is owner of 0 not 1)")
    scenario += cmta_fa2_contract.reassign([sp.record(token_id=sp.nat(1), original_holder=alice.address,replacement_holder=alice.address)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owner trying to batch reassign (Alice is owner of 0 not 1 and 2)")
    scenario += cmta_fa2_contract.reassign([sp.record(token_id=sp.nat(0), original_holder=alice.address,replacement_holder=alice.address), sp.record(token_id=sp.nat(1), original_holder=bob.address, replacement_holder=alice.address), sp.record(token_id=sp.nat(2), original_holder=dan.address, replacement_holder=alice.address)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owner reassigning to self")
    scenario += cmta_fa2_contract.reassign([sp.record(token_id=sp.nat(0), original_holder=alice.address, replacement_holder=alice.address)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owners reassigning tokens")
    scenario += cmta_fa2_contract.reassign([sp.record(token_id=sp.nat(1), original_holder=bob.address, replacement_holder=alice.address)]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.reassign([sp.record(token_id=sp.nat(2), original_holder=dan.address, replacement_holder=alice.address)]).run(sender=dan, valid=True)

    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(0, alice.address)] == 50)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(1, alice.address)] == 47)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(2, alice.address)] == 39)
    
    scenario.p("Correct owner reassigning non existings balances")
    scenario += cmta_fa2_contract.reassign([sp.record(token_id=sp.nat(1), original_holder=dan.address, replacement_holder=alice.address)]).run(sender=bob, valid=False)
    
    scenario.p("Can now only redeem if token on owner address")
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(1), amount=sp.nat(1))]).run(sender=bob, valid=False)
    scenario += cmta_fa2_contract.redeem([sp.record(token_id=sp.nat(2), amount=sp.nat(1))]).run(sender=dan, valid=False)

    
    scenario.h3("Destroy")
    scenario.p("Correct admin but not owner trying to destroy")
    scenario += cmta_fa2_contract.destroy([sp.record(token_id=sp.nat(0), holders=[alice.address, bob.address, dan.address])]).run(sender=administrator, valid=False)
    
    scenario.p("Incorrect owner trying to destroy (Alice is owner of 0 not 1)")
    scenario += cmta_fa2_contract.destroy([sp.record(token_id=sp.nat(1), holders=[alice.address, bob.address, dan.address])]).run(sender=alice, valid=False)
    
    scenario.p("Correct owner trying to batch destroy (Alice is owner of 0 not 1 and 2)")
    scenario += cmta_fa2_contract.destroy([sp.record(token_id=sp.nat(0), holders=[alice.address, bob.address, dan.address]), sp.record(token_id=sp.nat(1), holders=[alice.address, bob.address, dan.address]), sp.record(token_id=sp.nat(2), holders=[alice.address, bob.address, dan.address])]).run(sender=alice, valid=False)
    
    scenario.p("Correct owners destroying tokens")
    scenario += cmta_fa2_contract.destroy([sp.record(token_id=sp.nat(1), holders=[alice.address])]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.destroy([sp.record(token_id=sp.nat(2), holders=[alice.address])]).run(sender=dan, valid=True)

    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(0, alice.address)] == 50)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(1, bob.address)] == 47)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(2, dan.address)] == 39)
    
    scenario.p("Correct owner destroying non existings balances")
    scenario += cmta_fa2_contract.destroy([sp.record(token_id=sp.nat(1), holders=[alice.address, bob.address, dan.address])]).run(sender=bob, valid=False)
    
    scenario.h3("Pause")
    scenario.p("Correct admin but not owner trying to pause")
    scenario += cmta_fa2_contract.pause([sp.nat(0)]).run(sender=administrator, valid=False)
    
    scenario.p("Incorrect owner trying to pause (Alice is owner of 0 not 1)")
    scenario += cmta_fa2_contract.pause([sp.nat(1)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owner trying to batch pause (Alice is owner of 0 not 1 and 2)")
    scenario += cmta_fa2_contract.pause([sp.nat(0), sp.nat(1), sp.nat(2)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owners pauseing tokens")
    scenario += cmta_fa2_contract.pause([sp.nat(1)]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.pause([sp.nat(2)]).run(sender=dan, valid=True)
    
    
    scenario.h3("Unpause")
    scenario.p("Correct admin but not owner trying to unpause")
    scenario += cmta_fa2_contract.unpause([sp.nat(0)]).run(sender=administrator, valid=False)
    
    scenario.p("Incorrect owner trying to unpause (Alice is owner of 0 not 1)")
    scenario += cmta_fa2_contract.unpause([sp.nat(1)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owner trying to batch unpause (Alice is owner of 0 not 1 and 2)")
    scenario += cmta_fa2_contract.unpause([sp.nat(0), sp.nat(1), sp.nat(2)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owners unpauseing tokens")
    scenario += cmta_fa2_contract.unpause([sp.nat(1)]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.unpause([sp.nat(2)]).run(sender=dan, valid=True)
    
    scenario.h2("Token Holder Calls")
    scenario.h3("Transfer")
    scenario.p("Holder with no balance tries transfer")
    scenario += cmta_fa2_contract.transfer([sp.record(from_=bob.address, txs=[sp.record(to_=dan.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=bob, valid=False)
    
    scenario.p("Admin with no balance tries transfer")
    scenario += cmta_fa2_contract.transfer([sp.record(from_=administrator.address, txs=[sp.record(to_=dan.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=administrator, valid=False)
    
    scenario.p("Admin tries transfer of third parties balance")
    scenario += cmta_fa2_contract.transfer([sp.record(from_=alice.address, txs=[sp.record(to_=dan.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=administrator, valid=False)
    
    scenario.p("Owner performs initial transfer of own balance")
    scenario += cmta_fa2_contract.transfer([sp.record(from_=alice.address, txs=[sp.record(to_=dan.address, token_id=sp.nat(0), amount=sp.nat(10))])]).run(sender=alice, valid=True)
    
    scenario.p("Owner tries transfer of third party balance")
    scenario += cmta_fa2_contract.transfer([sp.record(from_=dan.address, txs=[sp.record(to_=bob.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=alice, valid=False)
    
    scenario.p("Holder transfers own balance")
    scenario += cmta_fa2_contract.transfer([sp.record(from_=dan.address, txs=[sp.record(to_=bob.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=dan, valid=True)
    
    scenario.p("Holder transfers too much")
    scenario += cmta_fa2_contract.transfer([sp.record(from_=dan.address, txs=[sp.record(to_=bob.address, token_id=sp.nat(0), amount=sp.nat(11))])]).run(sender=dan, valid=False)
    
    scenario.h3("Pause/Unpause")
    scenario.p("Holder transfers too much")
    scenario += cmta_fa2_contract.transfer([sp.record(from_=dan.address, txs=[sp.record(to_=bob.address, token_id=sp.nat(0), amount=sp.nat(11))])]).run(sender=dan, valid=False)
    
    scenario.p("Holder transfers paused token")
    scenario += cmta_fa2_contract.pause([sp.nat(0)]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.pause([sp.nat(1)]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.transfer([sp.record(from_=dan.address, txs=[sp.record(to_=bob.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=dan, valid=False)
    
    scenario.p("Holder transfers resumed token")
    scenario += cmta_fa2_contract.unpause([sp.nat(0)]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.transfer([sp.record(from_=dan.address, txs=[sp.record(to_=bob.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=dan, valid=True)
    
    scenario.h3("Identities")
    scenario.p("Holder discloses own identity")
    scenario += cmta_fa2_contract.set_identity(sp.bytes("0x11")).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.set_identity(sp.bytes("0x12")).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.set_identity(sp.bytes("0x13")).run(sender=dan, valid=True)
    
    scenario.h3("Rule Engine")
    allow_list_rule_engine_contract = AllowListRuleEngine()
    scenario += allow_list_rule_engine_contract
    scenario += allow_list_rule_engine_contract.add(alice.address)
    scenario += cmta_fa2_contract.set_rules([sp.record(token_id=sp.nat(0), rule_contract=allow_list_rule_engine_contract.address)]).run(sender=alice, valid=True)
    # scenario += cmta_fa2_contract.transfer([sp.record(from_=alice.address, txs=[sp.record(to_=dan.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=alice, valid=False)
    scenario += allow_list_rule_engine_contract.add(dan.address)
    scenario += cmta_fa2_contract.transfer([sp.record(from_=alice.address, txs=[sp.record(to_=dan.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=alice, valid=True)
    
    
 