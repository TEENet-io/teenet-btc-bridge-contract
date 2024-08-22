// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface TWBTCErrors {
    error TotalMintedExceedsMaxSupply(uint256 currentSupply);
}

contract TWBTC is ERC20, Ownable, TWBTCErrors {
    uint256 constant public MAX_BTC_SUPPLY = 21_000_000 * 10 ** 8;

    constructor(address owner_) ERC20("TEENet wrapped Bitcoin", "TWBTC") Ownable(owner_) {}

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);

        if (totalSupply() > MAX_BTC_SUPPLY) {
            revert TotalMintedExceedsMaxSupply(totalSupply());
        }
    }

    function burn(address from, uint256 amount) public onlyOwner {
        _burn(from, amount);
    }

    function decimals() public pure override returns (uint8) {
        return 8;
    }
}