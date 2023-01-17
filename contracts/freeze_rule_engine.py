import smartpy as sp
from contracts.cmta_fa2 import CMTAFA2ErrorMessage, ValidationTransfer
from contracts.fa2 import AdministrableErrorMessage

class FreezeRuleEngine(sp.Contract):
    def __init__(self, administrator, frozen_accounts={}):
        self.init(
            administrator=administrator,
            frozen_accounts=sp.big_map(frozen_accounts, tkey = sp.TAddress, tvalue = sp.TUnit)
        )

    @sp.onchain_view()
    def view_is_transfer_valid(self, validation_transfer):
        sp.set_type(validation_transfer, ValidationTransfer.get_type())
        sp.result(~self.data.frozen_accounts.contains(validation_transfer.from_)&~self.data.frozen_accounts.contains(validation_transfer.to_))

    @sp.entry_point
    def freeze_account(self, account):
        sp.verify(sp.sender == self.data.administrator, message = AdministrableErrorMessage.NOT_ADMIN)
        self.data.frozen_accounts[account] = sp.unit
    
    @sp.entry_point
    def unfreeze_account(self, account):
        sp.verify(sp.sender == self.data.administrator, message = AdministrableErrorMessage.NOT_ADMIN)
        del self.data.frozen_accounts[account]
