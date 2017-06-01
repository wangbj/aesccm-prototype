{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as S
import           Data.ByteString (ByteString)
import           Test.QuickCheck
import           Criterion.Main
import           Control.Monad
import           Data.Maybe
import           Crypto.Cipher.AES
import           Crypto.Cipher.Types
import           Crypto.Error

import           AESCCM

cipherInitNoErr :: BlockCipher c => ByteString -> c
cipherInitNoErr k = case cipherInit k of
  CryptoPassed a -> a
  CryptoFailed e -> error (show e)

key = cipherInitNoErr "1234567812345678" :: AES128
nonce = "8765432187654321" :: ByteString
adata = "4321432143214321" :: ByteString

bestL k
  | k <  65536 = 2
  | k >= 65536 = 2

bestL' k
  | k <  65536 = CCM_L2
  | k >= 65536 = CCM_L3

ccmTest input = ccmEncrypt 16 (bestL (S.length input)) key input nonce adata

gcmTest input = snd $ aeadSimpleEncrypt aead S.empty input 16
  where aead = throwCryptoError $ aeadInit AEAD_GCM key nonce

cryptoniteCcmTest input = snd $ aeadSimpleEncrypt aead S.empty input 16
  where aead      = throwCryptoError $ aeadInit (AEAD_CCM inputsize CCM_M16 (bestL' inputsize)) key nonce
        inputsize = S.length input

main = defaultMain [
        bgroup "aes128 gcm encrypt"
        [ bench ("inputsize: " ++ show datasize) (nf gcmTest (S.replicate datasize 0x42)) | datasize <- [1024, 16384, 262144, 4194304] ]
      , bgroup "aes128 (pure) ccm encrypt"
        [ bench ("inputsize: " ++ show datasize) (nf ccmTest (S.replicate datasize 0x42)) | datasize <- [1024, 16384, 262144, 4194304] ]
      , bgroup "aes128 (cryptonite) ccm encrypt"
        [ bench ("inputsize: " ++ show datasize) (nf cryptoniteCcmTest (S.replicate datasize 0x42)) | datasize <- [1024, 16384, 262144, 4194304] ]
    ]
