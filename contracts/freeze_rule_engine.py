import smartpy as sp
from contracts.cmta_fa2 import CMTAFA2ErrorMessage 
from contracts.fa2 import Transfer, AdministrableErrorMessage

class FreezeRuleEngine(sp.Contract):
    def __init__(self, administrator, frozen_accounts={}):
        self.init(
            administrator=administrator,
            frozen_accounts=sp.big_map(frozen_accounts, tkey = sp.TAddress, tvalue = sp.TUnit)
        ) 
        
    @sp.entry_point
    def validate_transfer(self, transfer):
        sp.set_type(transfer, Transfer.get_type())
        with sp.for_('tx', transfer.txs) as tx:
            sp.verify(~self.data.frozen_accounts.contains(transfer.from_), message=CMTAFA2ErrorMessage.CANNOT_TRANSFER)
            sp.verify(~self.data.frozen_accounts.contains(tx.to_), message=CMTAFA2ErrorMessage.CANNOT_TRANSFER)

    @sp.entry_point
    def freeze_account(self, account):
        sp.verify(sp.sender == self.data.administrator, message = AdministrableErrorMessage.NOT_ADMIN)
        self.data.frozen_accounts[account] = sp.unit
    
    @sp.entry_point
    def unfreeze_account(self, account):
        sp.verify(sp.sender == self.data.administrator, message = AdministrableErrorMessage.NOT_ADMIN)
        del self.data.frozen_accounts[account]
