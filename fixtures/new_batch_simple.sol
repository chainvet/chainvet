pragma solidity ^0.8.0;

contract NewBatchSimple {
    uint256 public price = 1 wei;

    function payout(address payable to) external {
        for (uint256 i = 0; i < 2; i++) {
            (bool ok,) = to.call{value: 1 wei}("");
            require(ok, "send failed");
        }
    }

    function trade(address payable to) external {
        uint256 p = price;
        (bool ok,) = to.call{value: p}("");
        require(ok, "x");
    }

    function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(h, v, r, s);
    }
}
