mod core;
mod options;
mod session;
mod socket;
mod storage;

use self::core::Connector;
pub use self::core::{CallError, ConnectorError, NotConnectedError, SessionError};
pub use self::options::{Connection, Options, DEFAULT_BRIDGE_URL};
pub use self::socket::SocketError;
use crate::protocol::{Metadata, Transaction};
use crate::uri::Uri;
use ethers_core::types::{Address, Bytes, Signature, H256};
use ethers_core::utils::keccak256;
use std::path::PathBuf;
use web3::signing;
use web3::types::Recovery;

#[derive(Debug)]
pub struct Client {
    connection: Connector,
}

impl Client {
    pub fn new(
        profile: impl Into<PathBuf>,
        meta: impl Into<Metadata>,
    ) -> Result<Self, ConnectorError> {
        Client::with_options(Options::new(profile, meta.into()))
    }

    pub fn with_options(options: Options) -> Result<Self, ConnectorError> {
        Ok(Client {
            connection: Connector::new(options)?,
        })
    }

    pub fn accounts(&self) -> Result<(Vec<Address>, u64), NotConnectedError> {
        self.connection.accounts()
    }

    pub async fn ensure_session<F>(&self, f: F) -> Result<(Vec<Address>, u64), SessionError>
    where
        F: FnOnce(Uri),
    {
        Ok(self.connection.ensure_session(f).await?)
    }

    pub async fn send_transaction(&self, transaction: Transaction) -> Result<H256, CallError> {
        Ok(self.connection.send_transaction(transaction).await?)
    }

    pub async fn sign_transaction(&self, transaction: Transaction) -> Result<Bytes, CallError> {
        Ok(self.connection.sign_transaction(transaction).await?)
    }

    pub async fn personal_sign(&self, data: &[&str]) -> Result<Signature, CallError> {
        let sig = self.connection.personal_sign(data).await?;
        Ok(sig.as_ref().try_into().unwrap())
    }

    pub fn close(self) -> Result<(), SocketError> {
        self.connection.close()
    }
}

pub fn verify_sig(msg: &str, sig: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let (sig, r) = Recovery::from_raw_signature(msg, sig)
        .unwrap()
        .as_signature()
        .unwrap();

    let message_hash = keccak256(msg.as_bytes());

    let address = signing::recover(message_hash.as_ref(), &sig, r)?;
    Ok(format!("{:?}", address))
}

#[cfg(test)]
mod tests {

    use super::*;
    use hex_literal::hex;

    #[test]
    fn recovery_signature() {
        // let msg = "Some data";
        let msg_hash = "1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655";
        let sig=   hex!("b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c");

        let addr = match verify_sig(msg_hash, &sig) {
            Ok(addr) => {
                println!("{}", addr);
                addr
            }
            Err(e) => {
                println!("{}", e);
                panic!("{}", e.to_string());
            }
        };
        assert_eq!(
            addr,
            "0x08901d616dad14aa9a8c5196591acd44ab827afd".to_string()
        );
    }
}
