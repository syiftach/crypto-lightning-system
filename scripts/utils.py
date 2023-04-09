from dataclasses import dataclass
from hexbytes import HexBytes
from typing import NewType, Tuple
from brownie import web3  # type: ignore
import eth_account

APPEAL_PERIOD = 5  # the appeal period in blocks.

Signature = NewType('Signature', Tuple[int, str, str])
EthereumAddress = NewType('EthereumAddress', str)
IPAddress = NewType('IPAddress', str)


@dataclass(frozen=True)
class ChannelStateMessage:
    contract_address: EthereumAddress
    balance1: int  # internal balance of the channel's creator
    balance2: int  # internal balance of the other party (not the creator)
    serial_number: int
    sig: Signature = Signature((0, "", ""))

    @property
    def message_hash(self) -> HexBytes:
        message = [self.contract_address,
                   self.balance1, self.balance2, self.serial_number]
        return HexBytes(web3.solidityKeccak(["address", "uint256", "uint256", "uint256"], message))


def sign(msg: ChannelStateMessage,
         address: EthereumAddress) -> ChannelStateMessage:
    """returns a new version of this state message, 
    signed by the  given ethereum Address"""
    return ChannelStateMessage(msg.contract_address, msg.balance1, msg.balance2, msg.serial_number,
                               _get_v_r_s(web3.eth.sign(address, msg.message_hash)))


def validate_signature(msg: ChannelStateMessage, pk: EthereumAddress) -> bool:
    """validates the signature of the channel state message"""
    final_msg = eth_account.messages.encode_defunct(msg.message_hash)
    return bool(web3.eth.account.recover_message(final_msg, vrs=msg.sig) == pk)


def _get_v_r_s(sig: str) -> Signature:
    """Converts the signature to a format of 3 numbers v,r,s that are accepted by ethereum"""
    v = web3.toInt(sig[-1])
    r = web3.toHex(sig[:32])
    s = web3.toHex(sig[32:64])
    if v < 27:
        v += 27
    return Signature((v, r, s))
