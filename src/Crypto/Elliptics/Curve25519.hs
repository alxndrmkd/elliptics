{-# LANGUAGE OverloadedStrings #-}

module Crypto.Elliptics.Curve25519
    -- * Constants
  ( curve25519KeyLength
  , curve25519SignatureLength
  -- * Types
  , PrivateKey
  , PublicKey
  , Signature
  , KeyPair(..)
  -- * Smart constructors
  , privateKey
  , publicKey
  , signature
  -- * Functions
  , privateKeyBytes
  , publicKeyBytes
  , signatureBytes
  , сurve25519Sign
  , curve25519Verify
  , curve25519Keygen
  , curve25519PrivateKeygen
  , keyPairgen
  ) where

import qualified Data.ByteString        as B
import           Data.ByteString.Unsafe
import           Foreign.C.Types
import           Foreign.Marshal.Alloc
import           Foreign.Ptr
import           System.IO.Unsafe

curve25519KeyLength :: Int
curve25519KeyLength = 32

curve25519SignatureLength :: Int
curve25519SignatureLength = 64

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --

newtype PrivateKey =
  Prv B.ByteString

newtype PublicKey =
  Pub B.ByteString

newtype Signature =
  Sig B.ByteString

data KeyPair = KeyPair
  { getPublicKey  :: !PublicKey
  , getPrivateKey :: !PrivateKey
  }

keyPairgen :: B.ByteString -> KeyPair
keyPairgen rnd = KeyPair xpub xprv
  where
    xprv = curve25519PrivateKeygen rnd
    xpub = curve25519Keygen xprv

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --

publicKeyBytes :: PublicKey -> B.ByteString
publicKeyBytes (Pub bs) = bs

publicKey :: B.ByteString -> Maybe PublicKey
publicKey bs =
  if B.length bs == curve25519KeyLength
    then Just (Pub bs)
    else Nothing

privateKeyBytes :: PrivateKey -> B.ByteString
privateKeyBytes (Prv bs) = bs

privateKey :: B.ByteString -> Maybe PrivateKey
privateKey bs =
  if B.length bs == curve25519KeyLength
    then Just (Prv bs)
    else Nothing

signatureBytes :: Signature -> B.ByteString
signatureBytes (Sig bs) = bs

signature :: B.ByteString -> Maybe Signature
signature bs =
  if B.length bs == curve25519SignatureLength
    then Just (Sig bs)
    else Nothing

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
foreign import ccall unsafe "curve25519_keygen" c_curve25519_keygen
  :: Ptr CChar -> Ptr CChar -> IO ()

curve25519Keygen :: PrivateKey -> PublicKey
curve25519Keygen (Prv xprv) =
  unsafePerformIO $
  B.useAsCString xprv $ \xprvPtr ->
    fmap Pub $
    allocaBytes curve25519KeyLength $ \xpubPtr -> do
      c_curve25519_keygen xpubPtr xprvPtr
      B.packCStringLen (xpubPtr, curve25519KeyLength)

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
foreign import ccall unsafe "curve25519_sign" c_curve25519_sign
  :: Ptr CChar ->
  Ptr CChar -> Ptr CChar -> CULong -> Ptr CChar -> IO CInt

сurve25519Sign :: PrivateKey -> B.ByteString -> B.ByteString -> Signature
сurve25519Sign (Prv xprv) msg random =
  unsafePerformIO $
    B.useAsCString xprv $ \xprvPtr ->
      B.useAsCStringLen msg $ \(msgPtr, msgLen) ->
        B.useAsCString random $ \rndPtr ->
          fmap Sig $
          allocaBytes curve25519SignatureLength $ \outPtr -> do
            c_curve25519_sign outPtr xprvPtr msgPtr (fromIntegral msgLen) rndPtr
            B.packCStringLen (outPtr, curve25519SignatureLength)

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
foreign import ccall unsafe "curve25519_verify" c_curve25519_verify
  :: Ptr CChar -> Ptr CChar -> Ptr CChar -> CULong -> IO CInt

curve25519Verify :: PublicKey -> Signature -> B.ByteString -> Bool
curve25519Verify (Pub xpub) (Sig sig) msg =
  unsafePerformIO $
  B.useAsCString xpub $ \xpubPtr ->
    B.useAsCString sig $ \sigPtr ->
      B.useAsCStringLen msg $ \(msgPtr, msgLen) -> do
        r <- c_curve25519_verify sigPtr xpubPtr msgPtr (fromIntegral msgLen)
        return $ r == 0

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
foreign import ccall unsafe "curve25519_private_keygen" c_curve25519_private_keygen
  :: Ptr CChar -> Ptr CChar -> IO ()

curve25519PrivateKeygen :: B.ByteString -> PrivateKey
curve25519PrivateKeygen random =
  unsafePerformIO $
    B.useAsCString random $ \rndPtr ->
      fmap Prv $
      allocaBytes curve25519KeyLength $ \outPtr -> do
        c_curve25519_private_keygen rndPtr outPtr
        B.packCStringLen (outPtr, curve25519KeyLength)
-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
