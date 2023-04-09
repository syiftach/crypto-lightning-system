from typing import Dict, Any, Tuple
from enum import Enum

from scripts.utils import IPAddress
import scripts.node as node


####### DO NOT CHANGE THE CONTENTS OF THIS FILE ##################


class Message(Enum):
    NOTIFY_OF_CHANNEL = 1
    RECEIVE_FUNDS = 2
    ACK_TRANSFER = 3


class Network:
    """This class is used to simulate communication between nodes in the payment channel network"""

    def __init__(self) -> None:
        self._nodes: Dict[str, node.LightningNode] = dict()
        self._paused = False

    def set_ip_address_of_node(self, node: "node.LightningNode", ip_address: IPAddress) -> None:
        """assigns an IP address to the node. All messages to that address will trigger methods on the node."""
        self._nodes[ip_address] = node

    def send_message(self, destination_ip: IPAddress, message: Message, *payload_args: Any) -> bool:
        """Use this function to send a message to the node at the given ip address.
        The message types are defined as constants of the class: 
        Network.NOTIFY_OF_CHANNEL
        Network.RECEIVE_FUNDS
        Network.ACK_TRANSFER
        Each calls the corresponding method on the LightningNode.
        """
        if destination_ip not in self._nodes or self._paused:
            return False

        self.process_message(destination_ip, message, payload_args)
        return True

    def process_message(self, destination_ip: IPAddress, message: Message, payload_args: Tuple[Any, ...]) -> None:
        if message == Message.NOTIFY_OF_CHANNEL:
            self._nodes[destination_ip].notify_of_channel(*payload_args)
        elif message == Message.RECEIVE_FUNDS:
            self._nodes[destination_ip].receive_funds(*payload_args)
        elif message == Message.ACK_TRANSFER:
            self._nodes[destination_ip].ack_transfer(*payload_args)
        else:
            raise ValueError("Unknown message type")

    def stop(self) -> None:
        """stops all communication through this class and drops all messages"""
        self._paused = True

    def resume(self) -> None:
        """resumes communication"""
        self._paused = False
