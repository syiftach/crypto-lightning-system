from __future__ import annotations
from typing import Dict, Optional, List, Set, Any
from brownie import Channel, chain  # type: ignore
from brownie.network.account import Account  # type: ignore
from netaddr import IPAddress

import scripts.network as network
from scripts.utils import APPEAL_PERIOD, ChannelStateMessage, sign, EthereumAddress, IPAddress, validate_signature, \
    Signature

from scripts.network import Message

ERR_MSG_UNKNOWN_CH_ADDR = 'cannot recognize given channel'
ERR_MSG_INVALID_AMOUNT = 'given amount should be greater than 0, and at most equal to balance of account'
ERR_MSG_CH_OPEN = 'channel is still open'
ERR_MSG_CH_CLOSED = 'channel is closed'
ERR_MSG_APPEAL_ENDED = 'appeal period has ended'
ERR_MSG_APPEAL_ON = 'appeal period is still on'
ERR_MSG_INVALID_STATE = 'given state has an unseen serial number'

"represents states enums of contract Channel"
OPEN = 0
CLOSE = 1

"default signature"
DEFAULT_SIG = Signature((0, '', ''))


class LightningNode:
    """represents a payment channel node that can support several payment channels."""

    def __init__(self, account: Account, networking_interface: network.Network, ip: IPAddress) -> None:
        """
        Creates a new node that uses the given ethereum account as a wallet, 
        communicates on the given network and has the provided ip address.
        All values are assumed to be legal.
        """
        # brownie eth-account object of this node
        self._account: Account = account
        # networking interface
        self._net: network.Network = networking_interface
        # ip address of this node
        self._ip: IPAddress = ip
        # low level call dict for interacting with solidity Channel contract
        self._call_dict: Dict[str, Any] = {'from': self._account.address, 'amount': 0}
        # channels that this node is participating in, and has funds >0 in it
        self._active_channels: Set[EthereumAddress] = set()
        # mapping from channel address to channelData
        self._addr_to_ch_data: Dict[EthereumAddress, ChannelData] = dict()
        # set of all known channel addresses
        self._ch_history: Set[EthereumAddress] = set()

    def get_list_of_channels(self) -> List[EthereumAddress]:
        """
        returns a list of channels managed by this node. The list will include all open channels, 
        as well as closed channels that still have the node's money in them.
        Channels are removed from the list once funds have been withdrawn from them.
        """
        return list(self._active_channels)

    def establish_channel(self, other_party_eth_address: EthereumAddress,
                          other_party_ip_address: IPAddress,
                          amount_in_wei: int) -> EthereumAddress:
        """
        Creates a new channel that connects the address of this node and the address of a peer.
        The channel is funded by the current node, using the given amount of money from the node's address.
        returns the address of the channel contract.
        Raises an exception if the amount given is not positive or if it exceeds the funds controlled by the account.
        The IPAddress and ethereum address of the other party are assumed to be correct.
        
        The other node should be notified of the channel creation through the network object using a
        NOTIFY_OF_CHANNEL message
        """
        # cope with bad parameters and raise exceptions accordingly
        if not isinstance(amount_in_wei, int) or amount_in_wei <= 0 or amount_in_wei > self._account.balance():
            raise ValueError(ERR_MSG_INVALID_AMOUNT)
        # set the msg.value when calling the payable constructor, and send it to the blockchain
        self._set_call_amount(amount_in_wei)
        new_ch = Channel.deploy(other_party_eth_address, APPEAL_PERIOD, self._call_dict)
        self._reset_call_amount()
        ch_address = EthereumAddress(new_ch.address)
        # update channel-managing DS
        self._active_channels.add(ch_address)
        ch_data = ChannelData(ch_address, other_party_ip_address, other_party_eth_address)
        self._addr_to_ch_data[ch_address] = ch_data
        # notify to channel peer
        self._net.send_message(other_party_ip_address, Message.NOTIFY_OF_CHANNEL, ch_address, self._ip)
        # add channel address to channel history
        self._ch_history.add(ch_address)
        return ch_address

    def get_eth_address(self) -> EthereumAddress:
        """
        returns the ethereum address of this node
        """
        return EthereumAddress(self._account.address)

    def get_ip_address(self) -> IPAddress:
        """
        returns the IP address of this node
        """
        return IPAddress(self._ip)

    def send(self, channel_address: EthereumAddress, amount_in_wei: int) -> None:
        """
        sends money in one of the open channels this node is participating in 
        and notifies the other node (via a RECEIVE_FUNDS message through the network object). 
        
        This operation should not send a transaction to the blockchain.
        The channel that should be used is identified by its contract's address.

        If the balance in the channel is insufficient, or if a node tries to send a 0 or negative amount,
        raise an exception (without messaging the other node).
        If the channel is already closed, raise an exception.
        """
        # check if channel is known to node
        if not self._is_ch_known(channel_address):
            raise ValueError(ERR_MSG_UNKNOWN_CH_ADDR)
        curr_state = self.get_current_channel_state(channel_address)
        # check for amount validity
        if not isinstance(amount_in_wei, int) \
                or amount_in_wei <= 0 \
                or amount_in_wei > self._get_state_balance(curr_state):
            raise ValueError(ERR_MSG_INVALID_AMOUNT)
        # check if channel is closed: cannot send money through the channel if it is closed
        if self._is_ch_closed(channel_address):
            raise ValueError(ERR_MSG_CH_CLOSED)
        # generate next state and append it to channel states log
        ch_data = self._get_ch_data(channel_address)
        next_state = self._generate_next_ch_state(curr_state, amount_in_wei)
        ch_data.add_state(next_state, self._account.address)
        # print(f'{self._ip} sending funds...')
        self._net.send_message(ch_data.ip_other, Message.RECEIVE_FUNDS, next_state)

    def get_current_channel_state(self, channel_address: EthereumAddress) -> ChannelStateMessage:
        """
        Gets the latest state of the channel that was accepted by the other node 
        (i.e., the last signed channel state message received from the other party).
        If the node is not aware of this channel, raise an exception.
        """
        # check that the channel is known to this node
        if not self._is_ch_known(channel_address):
            raise ValueError(ERR_MSG_UNKNOWN_CH_ADDR)
        # get last channel state and return it
        ch_data = self._get_ch_data(channel_address)
        return ch_data.latest_state_tuple.state

    def close_channel(self, channel_address: EthereumAddress,
                      state: Optional[ChannelStateMessage] = None) -> None:
        """
        Closes the channel at the given contract address.
        If a channel state is not provided, the node attempts to close the channel with the latest state that it has,
        otherwise, it uses the channel state that is provided (this will allow a node to try to cheat its peer). 
        Closing the channel begins the appeal period automatically.
        If the channel is already closed, throw an exception.
        The other node is *not* notified of the closed channel.
        """
        # make sure given channel address is known
        if not self._is_ch_known(channel_address):
            raise ValueError(ERR_MSG_UNKNOWN_CH_ADDR)
        # make sure channel is not already closed
        if self._is_ch_closed(channel_address):
            raise ValueError(ERR_MSG_CH_CLOSED)
        # retrieve channel and close it according to channel-message-state
        ch_data = self._get_ch_data(channel_address)
        # if no channel state was given, get the last approved one (signed by both peers)
        if state is None:
            state_close_tuple = ch_data.latest_state_tuple
            self._submit_state_to_contract(ch_data, state_close_tuple)
            return
        if channel_address != state.contract_address:
            raise ValueError('channel address does not match state contract address')
        # close the channel according to given state
        state_close_tuple = ch_data.get_state_tuple(state.serial_number)
        # if given state is with unseen serial number: attempt to close the channel
        # THIS SHOULD NOT WORK BUT THE EXERCISE INSTRUCTIONS REQUIRE TO MAKE AN ATTEMPT
        if state_close_tuple is None:
            # raise ValueError(ERR_MSG_UNKNOWN_STATE)
            v, r, s = state.sig
            ch_data.ch_instance.one_sided_close(state.balance1, state.balance2,
                                                state.serial_number, v, r, s, self._call_dict)
            return
        # if given state does not have a signature
        if state.sig == DEFAULT_SIG:
            # set given state to state tuple and submit state with exiting signatures
            close_tuple = StateTuple(state, state_close_tuple.sig1, state_close_tuple.sig2)
            self._submit_state_to_contract(ch_data, close_tuple)
            return
        # otherwise (signature is provided), try the following:
        # try to close channel with state.sig as signature of owner1
        try:
            state_tuple1 = StateTuple(state, state.sig, state_close_tuple.sig2)
            ch_data.sn_to_tuple[state.serial_number] = state_tuple1
            # submit state to blockchain
            self._submit_state_to_contract(ch_data, state_tuple1)
        # try to close channel with state.sig as signature of owner2
        except Exception:
            state_tuple2 = StateTuple(state, state_close_tuple.sig1, state.sig)
            ch_data.sn_to_tuple[state.serial_number] = state_tuple2
            # submit state to blockchain
            self._submit_state_to_contract(ch_data, state_tuple2)
        # set sn to original state tuple
        ch_data.sn_to_tuple[state.serial_number] = state_close_tuple

    def appeal_closed_chan(self, channel_address: EthereumAddress) -> None:
        """
        Checks if the channel at the given address needs to be appealed, i.e., if it was closed with an old
        channel state.
        If so, an appeal is sent to the blockchain.
        If the channel is still open, OR if the appeal period has passed: raises an exception.
        If the channel is closed but no appeal is needed, this method does nothing.
        """
        if not self._is_ch_known(channel_address):
            raise ValueError(ERR_MSG_UNKNOWN_CH_ADDR)
        ch_data = self._get_ch_data(channel_address)
        ch = ch_data.ch_instance
        # if the channel is still open, or if appeal period has ended, revert appeal request
        if not self._is_ch_closed(channel_address):
            raise ValueError(ERR_MSG_CH_CLOSED)
        if self._appeal_period_ended(channel_address):
            raise Exception(ERR_MSG_APPEAL_ENDED)
        curr_state = self.get_current_channel_state(channel_address)
        # check if appeal is needed
        if curr_state.serial_number > ch.latestSN():
            self._submit_state_to_contract(ch_data, ch_data.latest_state_tuple, appeal=True)

    def withdraw_funds(self, channel_address: EthereumAddress) -> None:
        """
        Allows the user to claim the funds from the given channel.
        The channel needs to exist, and be after the appeal period time.
        Otherwise an exception should be raised.
        After the funds are withdrawn successfully, the node forgets this channel (it no longer appears in its
        open channel lists).
        If the balance of this node in the channel is 0, there is no need to create a withdraw transaction on
        the blockchain.
        """
        # check if channel is known to node: otherwise it cannot interact with it
        if not self._is_ch_known(channel_address):
            raise ValueError(ERR_MSG_UNKNOWN_CH_ADDR)
        # check if channel is closed: a node can withdraw money only if channel is closed
        if not self._is_ch_closed(channel_address):
            raise ValueError(ERR_MSG_CH_OPEN)
        ch = self._get_ch_data(channel_address).ch_instance
        # if appeal period is not over yet, node cannot withdraw the money
        if not self._appeal_period_ended(channel_address):
            raise Exception(ERR_MSG_APPEAL_ON)
        # if balance of node is 0, there is no need to interact with the blockchain
        if ch.balances(self._account.address) == 0:
            # forget this channel: it is closed, and there are no funds that can be withdrawn
            self._active_channels.discard(channel_address)
            return
        # withdraw fund into this node account
        ch.withdraw_funds(self._account.address, self._call_dict)
        # forget this channel
        self._active_channels.discard(channel_address)

    # =========================== INCOMING_COMMUNICATION_METHODS =========================== #

    def notify_of_channel(self, channel_address: EthereumAddress, other_party_ip_address: IPAddress) -> None:
        """
        This method is called to notify the node that another node created a channel in which it is participating.
        The contract address for the channel is provided.

        The message is ignored if one of the following holds:
        1) This node is already aware of the channel
        2) The channel address that is provided does not involve this node as the second owner of the channel
        3) The channel is already closed
        4) The appeal period on the channel is too low
        """
        # check if channel is already known to node
        if self._is_ch_known(channel_address):
            return
        try:
            ch = Channel.at(channel_address)
        except Exception:
            return
        # check if this node is owner2 of this channel
        if ch.owner2() != self._account.address:
            return
        # check if channel is closed
        if self._is_ch_closed(channel_address):
            return
        # check if appeal period is long enough
        if ch.appealPeriod() < APPEAL_PERIOD:
            return
        # set new ChannelData and add it
        new_ch_data = ChannelData(channel_address, other_party_ip_address, ch.owner1())
        self._addr_to_ch_data[channel_address] = new_ch_data
        # update channels DS of node
        self._active_channels.add(channel_address)
        # add new channel sent from peer to channel history
        self._ch_history.add(channel_address)
        # print(f'({self._ip}) i was notified')

    def ack_transfer(self, state: ChannelStateMessage) -> None:
        """
        This method receives a confirmation from another node about a transfer.
        The confirmation is supposed to be a signed message containing the last state sent to the other party,
        but now signed by the other party.
        In fact, any message that is signed properly, with a larger serial number,
        and that does not strictly decrease the balance of this node, should be accepted here.
        If the channel in this message does not exist, or the message is not valid, it is simply ignored.
        """
        # validate given state
        if not self._validate_channel_state(state):
            return
        # check if balance of node was decreased
        ch_data = self._get_ch_data(state.contract_address)
        # get the state this node signed over, and still pending
        pending_state = ch_data.get_state(state.serial_number)
        if pending_state is None:
            return
        # check that the balance of this node in the acknowledged state is not lower than the pending state
        if self._get_state_balance(state) < self._get_state_balance(pending_state):
            return
        # update channel state log
        ch_data.add_signature(state, ch_data.address_other)

    def receive_funds(self, state: ChannelStateMessage) -> None:
        """
        A method that is called when to notify this node that it receives funds through the channel.
        A signed message with the new channel state is received and should be checked.
        If this message is not valid (bad serial number, signature, or amounts of money are not consistent with a
        transfer to this node) then this message is ignored.
        Otherwise, the same channel state message should be sent back, this time signed by the node as an
        ACK_TRANSFER message.
        """
        # check new channel state validity
        if not self._validate_channel_state(state):
            return
        # add new state: first the state signed by this node
        ch_data = self._get_ch_data(state.contract_address)
        state_signed = sign(state, self._account.address)
        ch_data.add_state(state_signed, self._account.address)
        # then: add signature of other node (given state)
        ch_data.add_signature(state, ch_data.address_other)
        # acknowledge state
        self._net.send_message(ch_data.ip_other, Message.ACK_TRANSFER, state_signed)

    # =========================== PROTECTED =========================== #

    def _set_call_amount(self, amount: int) -> None:
        """
        set msg.value amount in call dict when contracting a contract
        @param amount: int, value to set
        @return:
        """
        self._call_dict['amount'] = amount

    def _reset_call_amount(self) -> None:
        """
        resets the msg.value to 0
        @return:
        """
        self._call_dict['amount'] = 0

    def _is_ch_known(self, ch_addr: EthereumAddress) -> bool:
        """
        @param ch_addr: ethereum address
        @return: true if channel is known, false otherwise
        """
        return ch_addr in self._ch_history

    def _is_ch_closed(self, ch_address: EthereumAddress) -> bool:
        """
        @param ch_address: ethereum address
        @return: true if channel is closed, false otherwise
        """
        ch = Channel.at(ch_address)
        state = ch.chState()
        return state == CLOSE

    def _appeal_period_ended(self, ch_address: EthereumAddress) -> bool:
        """
        @param ch_address: ethereum address
        @return: true if appeal period has ended, false otherwise
        """
        ch = self._get_ch_data(ch_address).ch_instance
        return chain.height - ch.closedBlockNumber() >= APPEAL_PERIOD

    def _get_ch_data(self, ch_address: EthereumAddress) -> [ChannelData, None]:
        """
        @param ch_address: ethereum address
        @return: ch_data: ChannelData, instance holding the local data of the channel
        """
        ch_data = self._addr_to_ch_data.get(ch_address, None)
        # assert ch_data is not None
        return ch_data

    def _get_state_balance(self, state: ChannelStateMessage) -> int:
        """
        @param state: ChannelStateMessage, channel state
        @return: balance: int, balance of node in given state
        """

        ch = self._get_ch_data(state.contract_address).ch_instance
        if self._account.address == ch.owner1():
            return state.balance1
        # assert self._account.address == ch.owner2()
        return state.balance2

    def _generate_next_ch_state(self, state: ChannelStateMessage, amount: int) -> ChannelStateMessage:
        """
        generates a successor state with incremented serial number value
        @param state: channel state message
        @param amount: amount to transfer to other peer
        @return: next_state: ChannelStateMessage, next state signed by this node
        """
        ch = self._get_ch_data(state.contract_address).ch_instance
        # send money from owner1 to owner2
        if self._account.address == ch.owner1():
            balance1 = state.balance1 - amount
            balance2 = state.balance2 + amount
        # send money from owner2 to owner1
        else:
            # assert self._account.address == ch.owner2()
            balance1 = state.balance1 + amount
            balance2 = state.balance2 - amount
        # create next state with incremented serial number
        new_state = ChannelStateMessage(state.contract_address, balance1, balance2, state.serial_number + 1)
        return sign(new_state, self._account.address)

    def _validate_channel_state(self, state: ChannelStateMessage) -> bool:
        """
        validated the given channel state
        @param state: state to validate
        @return: true if state is valid, false otherwise
        """
        # check typing correctness of given state
        if not isinstance(state, ChannelStateMessage):
            return False
        if not isinstance(state.contract_address, str) \
                or not isinstance(state.serial_number, int) \
                or not isinstance(state.balance1, int) \
                or not isinstance(state.balance2, int):
            return False
        # check if channel is known to this node
        if not self._is_ch_known(state.contract_address):
            return False
        # check that the channel instance exists
        try:
            ch = Channel.at(state.contract_address)
        except Exception:
            return False
        # check serial number: given state should have greater (and not equal!) serial number
        # if curr_state has same serial number as given state, then node should not accept the given state
        # because curr_state is already signed by both peers
        curr_state = self.get_current_channel_state(state.contract_address)
        if state.serial_number <= curr_state.serial_number:
            return False
        # validate signature
        ch_data = self._get_ch_data(state.contract_address)
        if not validate_signature(state, ch_data.address_other):
            return False
        # validate balances amounts of new state: the sum should be equal to contract balance
        if ch_data.ch_instance.balance() != state.balance1 + state.balance2:
            return False
        return True

    def _submit_state_to_contract(self, ch_data: ChannelData, state_close_tuple: StateTuple, appeal=False) -> None:
        """
        submit given state to blockchain

        @param ch_data: channel data instance corresponding to state
        @param state_close_tuple: state tuple with signatures of both peers
        @param appeal: if true, this node wish to appeal another state to blockchain,
            if false, closes the channel normally
        @return:
        """
        state_close = state_close_tuple.state
        ch = ch_data.ch_instance
        # if submitting state-0 there is no need to validate any signature
        if state_close.serial_number == 0:
            v, r, s = state_close.sig
            ch.one_sided_close(state_close.balance1, state_close.balance2, 0, v, r, s, self._call_dict)
            return
        v1, r1, s1 = ch_data.get_my_sig(state_close.serial_number)
        v2, r2, s2 = ch_data.get_other_sig(state_close.serial_number)
        # call the contract: interact with the blockchain
        # submit state of other node
        ch.submitPeerChState(ch_data.address_other, state_close.balance1, state_close.balance2,
                             state_close.serial_number, v2, r2, s2, self._call_dict)
        # submit state of this node
        if not appeal:
            ch.one_sided_close(state_close.balance1, state_close.balance2, state_close.serial_number,
                               v1, r1, s1, self._call_dict)
        else:
            ch.appeal_closure(state_close.balance1, state_close.balance2, state_close.serial_number,
                              v1, r1, s1, self._call_dict)


class ChannelData:
    """
    represents a instance that holds the channel information with its corresponding channel state messages
    """

    def __init__(self, ch_address: EthereumAddress, ip_other: IPAddress, address_other: EthereumAddress) -> None:
        """
        init the channel data instance
        @param ch_address: ethereum address of other node
        @param ip_other: ip address of other node
        @param address_other: ethereum address of other node
        """
        # set addresses and channel instance
        self.ch_address: EthereumAddress = ch_address
        self.ch_instance: Channel = Channel.at(ch_address)
        self.ip_other: IPAddress = ip_other
        self.address_other: EthereumAddress = address_other
        # set latest state
        state0 = ChannelStateMessage(self.ch_instance.address, self.ch_instance.balance(), 0, 0)
        # latest (with largest sn) channel state that was signed by both peers
        self.latest_state_tuple: StateTuple = StateTuple(state0, DEFAULT_SIG, DEFAULT_SIG)
        # list of all states signed by both peers
        self.ready_states: List[StateTuple] = [self.latest_state_tuple]
        # mapping from channel state serial number to its corresponding StateTuple
        self.sn_to_tuple: Dict[int, StateTuple] = {0: self.latest_state_tuple}

    def __str__(self):
        return f'Ch-{self.ch_address[2:6]}'

    def __repr__(self):
        return f'Ch-{self.ch_address[2:6]},sn={self.latest_state_tuple.state.serial_number}'

    def add_state(self, state: ChannelStateMessage, address: EthereumAddress) -> None:
        """
        add the channel state signed by this node, to the state tuple
        @param state: channel state message to add
        @param address: ethereum address (should be address of caller node)
        @return:
        """
        if address == self.ch_instance.owner1():
            self.sn_to_tuple[state.serial_number] = StateTuple(state, sig1=state.sig)
        else:
            self.sn_to_tuple[state.serial_number] = StateTuple(state, sig2=state.sig)

    def add_signature(self, state: ChannelStateMessage, address: EthereumAddress) -> None:
        """
        add signature of other node to the state tuple
        the state given will be the one returned from get_current_state of LightningNode class.

        @param state: channel state signed by other node
        @param address: ethereum address of other node
        @return:
        """
        state_tuple = self.sn_to_tuple[state.serial_number]
        if address == self.ch_instance.owner1():
            state_tuple.sig1 = state.sig
            # set the state to in the tuple to be the one signed by the other party
            state_tuple.state = state
            self.latest_state_tuple = state_tuple
            self.ready_states.append(state_tuple)
        else:
            state_tuple.sig2 = state.sig
            # set the state to in the tuple to be the one signed by the other party
            state_tuple.state = state
            self.latest_state_tuple = state_tuple
            self.ready_states.append(state_tuple)

    def get_state_tuple(self, sn: int) -> [StateTuple, None]:
        """
        @param sn: int, serial number of state
        @return: state tuple with corresponding serial number, or none, if not exists
        """
        state_tuple = self.sn_to_tuple.get(sn, None)
        # assert state_tuple is not None
        return state_tuple

    def get_state(self, sn: int) -> [ChannelStateMessage, None]:
        """
        @param sn: int, serial number of state
        @return: state with corresponding serial number, or none, if not exists
        """
        state_tuple = self.sn_to_tuple.get(sn, None)
        # assert state_tuple is not None
        if state_tuple is None:
            return None
        return state_tuple.state

    def get_my_sig(self, sn: int) -> Signature:
        """
        @param sn: serial number of state
        @return: signature made by caller node
        """
        state_tuple = self.get_state_tuple(sn)
        # (caller is owner1 case) if owner2 is the other node, return sig1
        if self.ch_instance.owner2() == self.address_other:
            return state_tuple.sig1
        # (caller is owner2 case) if owner1 is address of caller node
        else:
            return state_tuple.sig2

    def get_other_sig(self, sn: int) -> Signature:
        """
        @param sn: serial number of state
        @return: signature made by other node
        """
        state_tuple = self.get_state_tuple(sn)
        # (caller is owner1 case) if owner2 is the other node, return sig2
        if self.ch_instance.owner2() == self.address_other:
            return state_tuple.sig2
        # (caller is owner2 case) if owner1 is address of caller node
        else:
            return state_tuple.sig1


class StateTuple:
    """
    class that represents a channel state tuple: (state data, sig1, sig2)
    """

    def __init__(self, ch_state: ChannelStateMessage,
                 sig1: Signature = DEFAULT_SIG, sig2: Signature = DEFAULT_SIG) -> None:
        self.state = ch_state  # channel state message
        self.sig1 = sig1  # signature of channel owner1
        self.sig2 = sig2  # signature of channel owner2

    def __str__(self):
        sig1 = 'ok' if self.sig1 != DEFAULT_SIG else 'X'
        sig2 = 'ok' if self.sig2 != DEFAULT_SIG else 'X'
        return f'(sn={self.state.serial_number},{sig1},{sig2})'

    def __repr__(self):
        return self.__str__()
