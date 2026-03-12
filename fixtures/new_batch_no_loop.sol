pragma solidity ^0.8.0;

contract NewBatchNoLoop {
    uint256 public price = 1 wei;

    function trade(address payable to) external {
        uint256 p = price;
        (bool ok,) = to.call{value: p}("");
        require(ok, "x");
    }

    function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(h, v, r, s);
    }
}
