//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


// Implement the API below. You can add functions as you wish, but do not change the behavior / signature of the 
// functions provided here.

contract Channel
{
    /**
    This contract will be deployed every time we establish a new payment channel between two participant.
    The creator of the channel also injects funds that can be sent (and later possibly sent back) in this channel
    */


    /*
    defines a state of the channel
    */
    enum State
    {
        OPEN, // ==0
        CLOSE // ==1
    }
    /*
    defines a submission of a channel state of a channel peer
    */
    struct PeerSubmit
    {
        uint balance1; // balance of owner1
        uint balance2; // balance of owner2
        uint sn; // serial number of submitted state
        bool sigVerified; // set to true if owner signed the channel state correctly
    }

    mapping(address => uint) public balances; // mapping from owner address to his channel balance
    mapping(address => PeerSubmit) public submit;
    address public owner1; // address of owner1, which corresponds to balance1
    address public owner2; // address of owner2, which corresponds to balance2
    uint public latestSN; // the latest serial number of state message to close this channel
    uint public appealPeriod; // the length (in blocks) of the appeal period
    State public chState; // current state of the channel
    uint public closedBlockNumber; // number of block when the channel was closed

    /**
    // creates a new payment channel with the other owner, and the given appeal period.
    // The constructor is payable. This way the creator puts money in the channel.
    */

    constructor(address payable _other_owner, uint _appeal_period_len) payable
    {
        require(msg.value > 0, "msg.value should be greater than 0");
        require(msg.sender != _other_owner, "cannot open channel between same account addresses");

        owner1 = msg.sender;
        owner2 = _other_owner;
        balances[msg.sender] = msg.value;
        appealPeriod = _appeal_period_len;
        latestSN = 0;
        chState = State.OPEN;
    }

    /**
    Closes the channel based on a message by one party.
    * If the serial number is 0, then the provided balance and signatures are ignored, and the channel is closed-
        according to the initial split, giving all the money to party 1.
    * Closing the channel starts the appeal period.
    * If any of the parameters are bad (signature,balance) the transaction reverts.
    * Additionally, the transactions would revert if the party closing the channel isn't one of the two participants.
    * _balance1 is the balance that belongs to the user that opened the channel. _balance2 is for the other user.
    */
    function one_sided_close(uint _balance1, uint _balance2, uint serial_num,
        uint8 v, bytes32 r, bytes32 s) external calledByOwner
    {
        // check that the channel is still open (can not be closed if already closed)
        require(chState == State.OPEN, "channel is already closed");

        // close the channel according to the initial split (do not update balances of channel peers)
        if (serial_num == 0)
        {
            // close the channel
            chState = State.CLOSE;
            closedBlockNumber = block.number;
            return;
        }
        // verify the given balances: make sure they sum is exactly the balance of the contract
        require(address(this).balance == (_balance1 + _balance2), "given balance values are invalid");
        // submit msg.sender's state
        submitPeerChState(msg.sender, _balance1, _balance2, serial_num, v, r, s);
        // verify owners submissions
        verifySubmissions();
        // update the balances and close the channel
        balances[owner1] = _balance1;
        balances[owner2] = _balance2;
        chState = State.CLOSE;
        latestSN = serial_num;
        closedBlockNumber = block.number;
        // reset submissions: contract should allow appealing while inside appeal period
        resetSubmissions();
    }

    /**
    appeals a one_sided_close.
    should show a signed message with a higher serial number.
    _balance1 belongs to the creator of the contract. _balance2 is the money going to the other user.
    this function reverts upon any problem:
        It can only be called during the appeal period.
        only one of the parties participating in the channel can appeal.
        the serial number, balance, and signature must all be provided correctly.
    */
    function appeal_closure(uint _balance1, uint _balance2, uint serial_num,
        uint8 v, bytes32 r, bytes32 s) external calledByOwner
    {
        // check that the channel is in a closed state
        require(chState == State.CLOSE);
        // verify serial number
        require(serial_num > latestSN, "can only appeal with newer channel state msg");
        // check that the appeal period has not yet ended
        require(block.number - closedBlockNumber < appealPeriod, "failed: appeal period has ended");
        // verify the given balances: make sure they sum is exactly the balance of the contract
        require(address(this).balance == (_balance1 + _balance2), "given balance values are invalid");
        // submit channel state msg
        submitPeerChState(msg.sender, _balance1, _balance2, serial_num, v, r, s);
        // verify owners submissions
        verifySubmissions();
        // re-close the channel: update the latestSN, the balances of owners, the the block number
        // the channel was close on
        latestSN = serial_num;
        closedBlockNumber = block.number;
        balances[owner1] = _balance1;
        balances[owner2] = _balance2;
        // reset submissions: contract should allow appealing while inside appeal period
        resetSubmissions();
    }
    /**
    // Sends all of the money belonging to msg.sender to the destination address provided.
    // this should only be possible if the channel is closed, and appeals are over.
    // This transaction should revert upon any error.
    */
    function withdraw_funds(address payable dest_address) external calledByOwner
    {
        // validate conditions: state should be close, appeal period is over, and amount should be positive
        require(chState == State.CLOSE, "failed to close channel: channel is open");
        require(block.number - closedBlockNumber >= appealPeriod, "appeal period is not over yet");
        require(balances[msg.sender] > 0, "no money in balance of caller");

        // update changes
        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;

        // commit changes
        (bool success,) = dest_address.call{value : amount}("");
        require(success, "failed to send money to destination address");
    }


    /**
    // the following utility function will help you check signatures in solidity:
    // v,r,s together make up the signature.
    // signerPubKey is the public key of the signer
    // contract_address, _balance1, _balance2, and serial_num constitute the message to be signed.
    // returns True if the sig checks out. False otherwise.
    */
    function _verifySig(address contract_address, uint _balance1, uint _balance2, uint serial_num, //<--- the message
        uint8 v, bytes32 r, bytes32 s, // <---- The signature
        address signerPubKey) pure public returns (bool)
    {
        // the message is made shorter:
        bytes32 hashMessage = keccak256(abi.encodePacked(contract_address, _balance1, _balance2, serial_num));

        //message signatures are prefixed in ethereum.
        bytes32 messageDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hashMessage));
        //If the signature is valid, ecrecover ought to return the signer's pubkey:
        return ecrecover(messageDigest, v, r, s) == signerPubKey;
    }

    /* ============================ HELPERS ============================ */

    /*
    submit a peer state.
    validates the state and updates the PeerSubmit struct
    */
    function submitPeerChState(address account, uint _balance1, uint _balance2, uint serial_num,
        uint8 v, bytes32 r, bytes32 s) public calledByOwner
    {
        // verify the signature validity
        bool verified = _verifySig(address(this), _balance1, _balance2, serial_num, v, r, s, account);
        require(verified, "could not verify signature");
        // update submit struct according to account address
        submit[account].balance1 = _balance1;
        submit[account].balance2 = _balance2;
        submit[account].sn = serial_num;
        submit[account].sigVerified = true;
    }

    /*
    resets the PeerSubmit struct to default values
    */
    function resetSubmissions() internal
    {
        // reset submission values for owners
        delete submit[owner1];
        delete submit[owner2];
    }

    /*
    verifies the submissions made by both owners
    */
    function verifySubmissions() internal
    {
        // check that both owners submitted the same state: all values should be equal
        require(submit[owner1].balance1 == submit[owner2].balance1, "submitted balances does not match");
        require(submit[owner1].balance2 == submit[owner2].balance2, "submitted balances does not match");
        require(submit[owner1].sn == submit[owner2].sn, "submitted sn's does not match");
        require(submit[owner1].sigVerified && submit[owner2].sigVerified, "failed to verify both signatures");
    }

    /* ============================ MODIFIERS ============================ */

    modifier calledByOwner()
    {
        // verify the msg caller
        require(msg.sender == owner1 || msg.sender == owner2, "this function can be called by channel owners only");
        // function call
        _;
    }
}