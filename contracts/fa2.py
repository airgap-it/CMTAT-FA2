import smartpy as sp

class FA2ErrorMessage:
    """Static enum used for the FA2 related errors, using the `FA2_` prefix"""
    PREFIX = "FA2_"
    TOKEN_UNDEFINED = "{}TOKEN_UNDEFINED".format(PREFIX)
    """This error is thrown if the token id used in to defined"""
    INSUFFICIENT_BALANCE = "{}INSUFFICIENT_BALANCE".format(PREFIX)
    """This error is thrown if the source address transfers an amount that exceeds its balance"""
    NOT_OWNER = "{}NOT_OWNER".format(PREFIX)
    """This error is thrown if not the owner is performing an action that he/she shouldn't"""
    NOT_OPERATOR = "{}NOT_OPERATOR".format(PREFIX)
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
        return sp.TRecord(owner = sp.TAddress, token_id = sp.TNat).layout(("owner", "token_id"))
        
    def make(token_id, owner):
        """Creates a typed ledger key"""
        return sp.set_type_expr(sp.record(owner = owner, token_id = token_id), LedgerKey.get_type())

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
            operators = sp.big_map(tkey=OperatorKey.get_type(), tvalue = sp.TUnit)
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
                sp.verify((sp.sender == transfer.from_) | self.data.operators.contains(operator_key), message=FA2ErrorMessage.NOT_OWNER)
                
                with sp.if_(tx.amount >= sp.nat(0)):
                    self.data.ledger[from_user] = sp.as_nat(self.data.ledger[from_user] - tx.amount)
                    self.data.ledger[to_user] = self.data.ledger.get(to_user, 0) + tx.amount
                    
                with sp.if_(self.data.ledger.get(from_user,sp.nat(0)) == sp.nat(0)):
                    del self.data.ledger[from_user]

    @sp.entry_point
    def update_operators(self, update_operators):
        """As per FA2 standard, allows a token owner to set an operator who will be allowed to perform transfers on her/his behalf"""
        sp.set_type(update_operators, UpdateOperator.get_batch_type())
        with sp.for_('update_operator', update_operators) as update_operator:
            with update_operator.match_cases() as argument:
                with argument.match("add_operator") as update:
                    sp.verify(update.owner == sp.sender, message=FA2ErrorMessage.NOT_OWNER)
                    operator_key = OperatorKey.make(update.token_id, update.owner, update.operator)
                    self.data.operators[operator_key] = sp.unit
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
        storage['administrator_allowmap'] = sp.set_type_expr(self.administrator_allowmap, sp.TMap(sp.TAddress, sp.TUnit))
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
                    sp.verify(self.data.administrator_allowmap.contains(sp.sender), message = AdministrableErrorMessage.NOT_ADMIN)
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

        administrator_ledger_key = sp.local("administrator_ledger_key", LedgerKey.make(token_id, sp.sender))

        sp.verify(self.data.administrators.get(administrator_ledger_key.value, sp.nat(0))==AdministratorState.IS_PROPOSED_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        self.data.administrators[administrator_ledger_key.value] = AdministratorState.IS_ADMIN
    
    @sp.entry_point
    def remove_administrator(self, token_id, administrator_to_remove):
        """This removes a administrator entry entirely from the map"""
        sp.set_type(token_id, sp.TNat)
        sp.set_type(administrator_to_remove, sp.TAddress)

        administrator_ledger_key = LedgerKey.make(token_id, sp.sender)
        administrator_to_remove_key = LedgerKey.make(token_id, administrator_to_remove)

        sp.verify(self.data.administrators.get(administrator_ledger_key, sp.nat(0))==AdministratorState.IS_ADMIN, message = AdministrableErrorMessage.NOT_ADMIN)
        del self.data.administrators[administrator_to_remove_key]