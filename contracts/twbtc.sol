// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract TWBTC is ERC20, Ownable{
    constructor(address owner_) ERC20("TEENet wrapped Bitcoin", "TWBTC") Ownable(owner_) {}

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) public onlyOwner {
        _burn(from, amount);
    }

	function decimals() public pure override returns (uint8) {
        return 8;
    }
}