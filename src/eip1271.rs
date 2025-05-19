use alloy::{
    primitives::{Address, Bytes, FixedBytes},
    providers::{
        Identity, RootProvider,
        fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    },
    sol,
};
use crate::VerificationError;

pub type AlloyProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

sol! {
    #[sol(rpc)]
    contract ERC1271 {
      /// bytes4(keccak256("isValidSignature(bytes32,bytes)")
      bytes4 constant internal MAGICVALUE = 0x1626ba7e;

      /// /**
      ///  * @dev Should return whether the signature provided is valid for the provided hash
      ///  * @param _hash      Hash of the data to be signed
      ///  * @param _signature Signature byte array associated with _hash
      ///  *
      ///  * MUST return the bytes4 magic value 0x1626ba7e when function passes.
      ///  * MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5)
      ///  * MUST allow external calls
      ///  */
      function isValidSignature(
        bytes32 _hash,
        bytes memory _signature)
        public
        view
        returns (bytes4 magicValue);
    }
}

pub async fn verify_eip1271(
    address: Address,
    message_hash: FixedBytes<32>,
    signature: Bytes,
    provider: &AlloyProvider,
) -> Result<bool, VerificationError> {
    let contract = ERC1271::new(address, provider);
    let res = contract
        .isValidSignature(message_hash, signature)
        .call()
        .await;
    match res {
        Ok(FixedBytes([22, 38, 186, 126])) => Ok(true),
        Ok(FixedBytes([255, 255, 255, 255])) => Ok(false),
        Ok(_) => Err(VerificationError::Eip1271NonCompliant)?,
        Err(e) => Err(VerificationError::ContractCall(e))?,
    }
}
