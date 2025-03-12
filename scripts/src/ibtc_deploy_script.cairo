use sncast_std::{declare, deploy, invoke, call, DeclareResultTrait, get_nonce, FeeSettings, StrkFeeSettings};

// The example below uses a contract deployed to the Sepolia testnet
fn main() {
    // // Deploy IBTC
    // let owner = contract_address_const::<0x077271d4fab7c232411cee7a677c16b67828128240171c7d95ed63624cff1b79>();
    // let ibtc_admin = contract_address_const::<0x077271d4fab7c232411cee7a677c16b67828128240171c7d95ed63624cff1b79>();

    // let ibtc_token_calldata: Array<felt252> = array![owner.into()];
    // let ibtc_token_address = utils::declare_and_deploy("IBTCToken", ibtc_token_calldata);
    // let ibtc_token_safe = IBTCTokenABISafeDispatcher { contract_address: ibtc_token_address };
    // let ibtc_token = IBTCTokenABIDispatcher { contract_address: ibtc_token_address };

    
    // // Deploy IBTCManager
    // let BTC_FEE_RECIPIENT: felt252 = 0x000001;
    // let threshold: u32 = 3;
    // let ibtc_manager_calldata: Array<felt252> = array![
    //     owner.into(), // owner
    //     ibtc_admin.into(), // admin
    //     threshold.into(),
    //     ibtc_token_address.into(), // ibtc address
    //     BTC_FEE_RECIPIENT // btc fee recipient
    // ];
    // let ibtc_manager_address = utils::declare_and_deploy("IBTCManager", ibtc_manager_calldata);
    // let ibtc_manager_safe = IBTCManagerABISafeDispatcher { contract_address: ibtc_manager_address };
    // let ibtc_manager = IBTCManagerABIDispatcher { contract_address: ibtc_manager_address };

    let max_fee = 999999999999999;
    let salt = 0x3;

    let declare_nonce = get_nonce('latest');

    let declare_result = declare(
        "IBTCToken",
        FeeSettings::Strk(StrkFeeSettings {
            max_fee: Option::Some(max_fee), max_gas: Option::None, max_gas_unit_price: Option::None
        }),
        Option::Some(declare_nonce)
    )
        .expect('IBTCToken declare failed');

    let class_hash = declare_result.class_hash();
    let deploy_nonce = get_nonce('pending');

    let deploy_result = deploy(
        *class_hash,
        ArrayTrait::new(),
        Option::Some(salt),
        true,
        FeeSettings::Strk(StrkFeeSettings {
            max_fee: Option::Some(max_fee), max_gas: Option::None, max_gas_unit_price: Option::None
        }),
        Option::Some(deploy_nonce)
    )
        .expect('IBTCToken deploy failed');

    assert(deploy_result.transaction_hash != 0, deploy_result.transaction_hash);

    let call_result = call(deploy_result.contract_address, selector!("name"), array![])
        .expect('IBTCToken call failed');

    assert(call_result.data == array!['IBTC'], *call_result.data.at(0));
}