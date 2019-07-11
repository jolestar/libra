use core::borrow::Borrow;
use std::collections::BTreeMap;
use std::convert::TryInto;

use failure::prelude::*;
use state_view::StateView;
use types::access_path::AccessPath;
use types::account_state_blob::AccountStateBlob;
use types::language_storage::ModuleId;
use vm::CompiledModule;
use vm_runtime::code_cache::module_adapter::ModuleFetcher;

use crate::client_proxy::ClientProxy;
use crate::grpc_client::GRPCClient;

pub struct RpcModuleFetcher<'c> {
    client: &'c ClientProxy,
}

impl<'c> RpcModuleFetcher<'c> {
    pub fn new(client: &'c ClientProxy) -> Self {
        RpcModuleFetcher { client }
    }
}

impl<'c> ModuleFetcher for RpcModuleFetcher<'c> {
    fn get_module(&self, key: &ModuleId) -> Option<CompiledModule> {
        let AccessPath { address, path } = AccessPath::code_access_path(key);
        let (account_bob, version) = self.client.client.get_account_blob(address).unwrap();
        match get_account_data(account_bob, &path) {
            Some(module_blob) => match CompiledModule::deserialize(&module_blob) {
                Ok(module) => Some(module),
                Err(_) => None,
            },
            None => None
        }
    }
}


pub struct LocalDataStore<'c> {
    client: &'c ClientProxy,
}

impl<'c> LocalDataStore<'c> {
    pub fn new(client: &'c ClientProxy) -> Self {
        LocalDataStore { client }
    }
}

fn get_account_data(account_bob: Option<AccountStateBlob>, path: &Vec<u8>) -> Option<Vec<u8>> {
    let map: BTreeMap<Vec<u8>, Vec<u8>> = match account_bob {
        Some(bob) => bob.borrow().try_into().unwrap(),
        None => BTreeMap::new(),
    };
    match map.get(path) {
        Some(v) => Some(v.clone()),
        None => None,
    }
}

impl<'c> StateView for LocalDataStore<'c> {
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        let AccessPath { address, path } = access_path;
        let (account_bob, version) = self.client.client.get_account_blob(*address)?;
        Ok(get_account_data(account_bob, path))
    }

    fn multi_get(&self, access_paths: &[AccessPath]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut vec = vec![];
        for path in access_paths {
            vec.push(self.get(path)?);
        }
        Ok(vec)
    }

    fn is_genesis(&self) -> bool {
        false
    }
}


pub struct LocalExecutor {}


impl LocalExecutor {}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::process::exit;
    use std::sync::Arc;

    use config::config::VMPublishingOption;
    use crypto::{
        hash::{
            ACCUMULATOR_PLACEHOLDER_HASH, CryptoHash, GENESIS_BLOCK_ID, SPARSE_MERKLE_PLACEHOLDER_HASH,
            TestOnlyHash, TransactionAccumulatorHasher,
        },
        HashValue,
        signing::generate_keypair,
    };
    use crypto::signing::KeyPair;
    use types::account_address::AccountAddress;
    use types::test_helpers::transaction_test_helpers::*;
    use types::transaction::{RawTransaction, SignatureCheckedTransaction, SignedTransaction};
    use types::transaction_helpers::{create_signed_txn, TransactionSigner};
    use types::validator_verifier::ValidatorVerifier;
    use types::vm_error::VMStatus::Verification;
    use vm::file_format::CompiledScriptMut;
    use vm::transaction_metadata::TransactionMetadata;
    use vm_cache_map::Arena;
    use vm_genesis::encode_transfer_program;
    use vm_runtime::code_cache::module_cache::{BlockModuleCache, VMModuleCache};
    use vm_runtime::code_cache::script_cache::ScriptCache;
    use vm_runtime::data_cache::BlockDataCache;
    use vm_runtime::process_txn::execute::ExecutedTransaction;
    use vm_runtime::process_txn::ProcessTransaction;
    use vm_runtime::process_txn::validate::{ValidatedTransaction, ValidationMode};
    use vm_runtime::process_txn::verify::VerifiedTransaction;
    use vm_runtime::txn_executor::TransactionExecutor;

    use crate::client_proxy::{AddressAndIndex, ClientProxy};
    use crate::grpc_client::GRPCClient;
    use crate::local_executor::{LocalDataStore, RpcModuleFetcher};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_executor() {
        let host = "localhost";
        let port = "64327";

        let validators = HashMap::new();
        let validator_verifier = Arc::new(ValidatorVerifier::new(validators));

        let validator_set_file = "/var/folders/by/8jj_3yzx4072w19vb_m934wc0000gn/T/.tmpqltO9z/trusted_peers.config.toml";
        let faucet_account_file = "/var/folders/by/8jj_3yzx4072w19vb_m934wc0000gn/T/keypair.3IVRhkp4ueND/temp_faucet_keys";
        let mut client = ClientProxy::new(host, port, validator_set_file, faucet_account_file, false, None, None).unwrap();
        //GRPCClient::new(host, port, validator_verifier).unwrap();
        client.test_validator_connection().unwrap();

        //let raw_tx = RawTransaction::new()
        let AddressAndIndex { address, index } = client.create_next_account(false).unwrap();

        client.mint_coins_with_local_faucet_account(&address, 1000000000, true).unwrap();

        let allocator = Arena::new();
        let vm_cache = VMModuleCache::new(&allocator);
        let fetcher = RpcModuleFetcher::new(&client);
        let module_cache = BlockModuleCache::new(&vm_cache, fetcher);

        let data_view = LocalDataStore::new(&client);
        let data_cache = BlockDataCache::new(&data_view);


        let sender_account = &client.accounts[0];

        let signer: Box<&dyn TransactionSigner> = match &sender_account.key_pair {
            Some(key_pair) => Box::new(key_pair),
            None => Box::new(&client.wallet),
        };


        let recipient = AccountAddress::random();

        let program = encode_transfer_program(&recipient, 100);

        let expiration_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 10;

        let signed_txn = create_signed_txn(*signer, program.clone(), address, 0, 10000, 1, expiration_time as i64).unwrap();
//        let signed_txn = get_test_unchecked_txn(
//            address,
//            0,
//            private_key,
//            public_key,
//            Some(program.clone()),
//        );

        let txn_data = TransactionMetadata::new(&signed_txn);
        //let executor = TransactionExecutor::new(module_cache, &data_cache, txn_data);

        let (code, args, module_bytes) = program.into_inner();
        //debug!("[VM] Script to execute: {:?}", script);
        //let script = CompiledScriptMut::des
        //executor.execute_function(program.)
        let signed_checked_txn = signed_txn.check_signature().unwrap();
        let process_tx = ProcessTransaction::new(signed_checked_txn, module_cache, &data_cache, &allocator);
        let mut validate_tx = ValidatedTransaction::new(process_tx, ValidationMode::Executing, &VMPublishingOption::Open).unwrap();
        let verify_tx = VerifiedTransaction::new(validate_tx).unwrap();

        let script_cache = ScriptCache::new(&allocator);
        let execute_tx = ExecutedTransaction::new(verify_tx, &script_cache);
        let output = execute_tx.into_output();
        println!("{:#?}", output);
    }
}
