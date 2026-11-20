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
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);

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
        require(a > 0, "empty");
        safeBalances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send failed");
    }

    function grant(address payable to, uint256 amount) external onlyOwner {
        require(to != address(0), "zero");
        to.transfer(amount);
    }

    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "empty");
        deposits[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function proxyCall(address target, bytes calldata data) external onlyOwner {
        require(target != address(0), "zero");
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }

    function setAdmin(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero");
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    function noFunds() external view returns (bool) {
        // slither-disable-next-line incorrect-equality
        return address(this).balance == 0;
    }
}