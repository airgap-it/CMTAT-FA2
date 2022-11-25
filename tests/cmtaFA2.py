import smartpy as sp

from contracts.cmtaFA2 import CMTAFA2, LedgerKey, AllowListRuleEngine, SnapshotLedgerKey

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
   

    scenario.h3("Issuing")
    scenario.p("Correct admin but not owner trying to mint")
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(0), amount=sp.nat(100), address=administrator.address)]).run(sender=administrator, valid=False)
    
    scenario.p("Incorrect owner trying to mint (Alice is owner of 0 not 1)")
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(1), amount=sp.nat(100), address=alice.address)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owner trying to batch mint (Alice is owner of 0 not 1 and 2)")
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(0), amount=sp.nat(100), address=alice.address), sp.record(token_id=sp.nat(1), amount=sp.nat(100), address=alice.address), sp.record(token_id=sp.nat(2), amount=sp.nat(100), address=alice.address)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owners issuing tokens")
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(0), amount=sp.nat(100), address=alice.address)]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(1), amount=sp.nat(100), address=bob.address)]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(2), amount=sp.nat(100), address=dan.address)]).run(sender=dan, valid=True)
    
    scenario.p("Correct owners issuing additional amounts of tokens")
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(0), amount=sp.nat(101), address=alice.address)]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(1), amount=sp.nat(101), address=bob.address)]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(2), amount=sp.nat(101), address=dan.address)]).run(sender=dan, valid=True)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(0, alice.address)] == 201)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(1, bob.address)] == 201)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(2, dan.address)] == 201)
    
    scenario.h3("Redemption")
    scenario.p("Correct admin but not owner trying to burn")
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(0), amount=sp.nat(100), address=administrator.address)]).run(sender=administrator, valid=False)
    
    scenario.p("Incorrect owner trying to burn (Alice is owner of 0 not 1)")
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(1), amount=sp.nat(100), address=alice.address)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owner trying to batch burn (Alice is owner of 0 not 1 and 2)")
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(0), amount=sp.nat(100), address=alice.address), sp.record(token_id=sp.nat(1), amount=sp.nat(100), address=alice.address), sp.record(token_id=sp.nat(1), amount=sp.nat(100), address=alice.address)]).run(sender=alice, valid=False)
    
    scenario.p("Correct owners burning tokens")
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(0), amount=sp.nat(100), address=alice.address)]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(1), amount=sp.nat(100), address=bob.address)]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(2), amount=sp.nat(100), address=dan.address)]).run(sender=dan, valid=True)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(0, alice.address)] == 101)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(1, bob.address)] == 101)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(2, dan.address)] == 101)
    
    scenario.p("Cannot burn more than owner has")
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(0), amount=sp.nat(201), address=alice.address)]).run(sender=alice, valid=False)
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(1), amount=sp.nat(201), address=bob.address)]).run(sender=bob, valid=False)
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(2), amount=sp.nat(201), address=dan.address)]).run(sender=dan, valid=False)
    
    scenario.p("Correct owners burning additional amounts of tokens")
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(0), amount=sp.nat(101), address=alice.address)]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(1), amount=sp.nat(101), address=bob.address)]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(2), amount=sp.nat(101), address=dan.address)]).run(sender=dan, valid=True)
    scenario.verify(~cmta_fa2_contract.data.ledger.contains(LedgerKey.make(0, alice.address)))
    scenario.verify(~cmta_fa2_contract.data.ledger.contains(LedgerKey.make(1, bob.address)))
    scenario.verify(~cmta_fa2_contract.data.ledger.contains(LedgerKey.make(2, dan.address)))
    

    
    scenario.h3("Reassign")
    scenario.p("Bootstrapping by issuing some tokens")
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(0), amount=sp.nat(50), address=alice.address)]).run(sender=alice, valid=True)
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(1), amount=sp.nat(47), address=alice.address)]).run(sender=bob, valid=True)
    scenario += cmta_fa2_contract.mint([sp.record(token_id=sp.nat(2), amount=sp.nat(39), address=alice.address)]).run(sender=dan, valid=True)
       
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(0, alice.address)] == 50)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(1, alice.address)] == 47)
    scenario.verify(cmta_fa2_contract.data.ledger[LedgerKey.make(2, alice.address)] == 39)
    
    scenario.p("Can now only burn if token on owner address")
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(1), amount=sp.nat(1), address=bob.address)]).run(sender=bob, valid=False)
    scenario += cmta_fa2_contract.burn([sp.record(token_id=sp.nat(2), amount=sp.nat(1), address=dan.address)]).run(sender=dan, valid=False)

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
    scenario += cmta_fa2_contract.set_rule_engines([sp.record(token_id=sp.nat(0), rule_contract=allow_list_rule_engine_contract.address)]).run(sender=alice, valid=True)
    # scenario += cmta_fa2_contract.transfer([sp.record(from_=alice.address, txs=[sp.record(to_=dan.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=alice, valid=False)
    scenario += allow_list_rule_engine_contract.add(dan.address)
    scenario += cmta_fa2_contract.transfer([sp.record(from_=alice.address, txs=[sp.record(to_=dan.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=alice, valid=True)
    scenario += allow_list_rule_engine_contract.add(bob.address)

    scenario.h3("Snapshots")
    snapshot_time = sp.timestamp(1)
    token_id = sp.nat(0)

    scenario.p("Bob cannot schedule snapshot")
    scenario += cmta_fa2_contract.schedule_snapshot(sp.record(token_id=token_id, snapshot_timestamp=snapshot_time)).run(sender=bob, valid=False)

    scenario.p("Only owner can schedule snapshot")
    scenario += cmta_fa2_contract.schedule_snapshot(sp.record(token_id=token_id, snapshot_timestamp=snapshot_time)).run(sender=alice, valid=True)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, snapshot_time))==39)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, snapshot_time))==9)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, snapshot_time))==2)

    scenario.p("Alice now transfers")
    future_time = sp.timestamp(2)
    scenario += cmta_fa2_contract.transfer([sp.record(from_=alice.address, txs=[sp.record(to_=dan.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=alice, now=future_time, valid=True)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, snapshot_time))==39)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, snapshot_time))==9)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, snapshot_time))==2)
    
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, future_time))==38)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, future_time))==10)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, future_time))==2)

    scenario.p("New schedule")
    snapshot_time = sp.timestamp(3)
    scenario += cmta_fa2_contract.schedule_snapshot(sp.record(token_id=token_id, snapshot_timestamp=snapshot_time)).run(sender=alice, valid=True, now=future_time)
    future_time = sp.timestamp(4)
    scenario += cmta_fa2_contract.transfer([sp.record(from_=alice.address, txs=[sp.record(to_=bob.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=alice, now=future_time, valid=True)
    
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, snapshot_time))==38)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, snapshot_time))==10)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, snapshot_time))==2)
    
    previous_snapshot_time = sp.timestamp(1)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, previous_snapshot_time))==39)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, previous_snapshot_time))==9)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, previous_snapshot_time))==2)

    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, future_time))==37)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, future_time))==10)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, future_time))==3)

    scenario.p("Yet another schedule")
    snapshot_time = sp.timestamp(5)
    scenario += cmta_fa2_contract.schedule_snapshot(sp.record(token_id=token_id, snapshot_timestamp=snapshot_time)).run(sender=alice, valid=True, now=future_time)
    future_time = sp.timestamp(6)
    scenario += cmta_fa2_contract.transfer([sp.record(from_=alice.address, txs=[sp.record(to_=bob.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=alice, now=future_time, valid=True)
    
    previous_snapshot_time = sp.timestamp(3)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, previous_snapshot_time))==38)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, previous_snapshot_time))==10)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, previous_snapshot_time))==2)

    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, future_time))==36)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, future_time))==10)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, future_time))==4)

    snapshot_time = sp.timestamp(7)
    scenario += cmta_fa2_contract.schedule_snapshot(sp.record(token_id=token_id, snapshot_timestamp=snapshot_time)).run(sender=alice, valid=True, now=future_time)
    future_time = sp.timestamp(8)
    scenario += cmta_fa2_contract.transfer([sp.record(from_=alice.address, txs=[sp.record(to_=bob.address, token_id=sp.nat(0), amount=sp.nat(1))])]).run(sender=alice, now=future_time, valid=True)

    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, snapshot_time))==36)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, snapshot_time))==10)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, snapshot_time))==4)

    previous_snapshot_time = sp.timestamp(5)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, previous_snapshot_time))==37)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, previous_snapshot_time))==10)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, previous_snapshot_time))==3)

    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, alice.address, future_time))==35)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, dan.address, future_time))==10)
    scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, future_time))==5)


    scenario.p("Snapshot total Supplies")
    #scenario.verify(cmta_fa2_contract.view_snapshot_balance_of(SnapshotLedgerKey.make(token_id, bob.address, future_time))==5)