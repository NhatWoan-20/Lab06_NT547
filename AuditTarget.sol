// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// NT547 - Lab 06 - Hop dong rieng cua MSSV 22521203. KHONG deploy len mainnet.

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract TipJar_1203 {
    address public owner;
    mapping(address => uint256) public deposits;
    bool private locked;
    mapping(address => uint256) public safeBalances;

    event Deposited(address indexed who, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier exclusive() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function stake() external payable {
        deposits[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function ownerWithdraw(uint256 amount) external onlyOwner {
        (bool ok, ) = payable(owner).call{value: amount}("");
        require(ok, "withdraw failed");
    }

    function depositSafe() external payable exclusive {
        safeBalances[msg.sender] += msg.value;
    }

    function exitSafe() external exclusive {
        uint256 a = safeBalances[msg.sender];
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send failed");
        safeBalances[msg.sender] = 0;
    }

    function grant(address payable to, uint256 amount) external {
        to.transfer(amount);
    }

    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "empty");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        deposits[msg.sender] = 0;
    }

    function proxyCall(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    function setAdmin(address newOwner) external {
        require(tx.origin == owner, "not owner");
        require(newOwner != address(0), "zero");
        owner = newOwner;
    }

    function noFunds() external view returns (bool) {
        return address(this).balance == 0;
    }
}
