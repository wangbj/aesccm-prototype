{-# LANGUAGE FlexibleContexts, OverloadedStrings, ScopedTypeVariables #-}
module AESCCM (
    ccmEncrypt
  , ccmEncryptSimple
  ) where

import qualified Data.ByteString as S
import           Data.ByteString (ByteString)
import qualified Data.ByteArray as BA

import Data.Bits
import Data.Word
import Data.Monoid
import Data.Maybe

import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error

encodeFlags :: Bool -> Int -> Int -> Word8
encodeFlags hasAdata m' l' = fromIntegral $ 64 * (if hasAdata then 1 else 0) + 8 * m' + l'

-- | encode big endian int to bytestring as word64
word64be :: Int -> ByteString
word64be = leftpad 8 . S.pack . reverse . go 
  where go k
          | k == 0   = []
          | k < 256  = [fromIntegral k]
          | k >= 256 = (fromIntegral k .&. 0xff) : go (k `shiftR` 8)
        leftpad n s = S.replicate (n - S.length s) 0 <> s

bitfields x i j = fromIntegral ((x `shiftR` j) .&. m)
  where l = j - i + 1
        m = 1 `shiftL` l - 1

-- |encode l(a)
encodeLa :: Word64 -> ByteString
encodeLa la
  | la < 2^16 - 2^8 = S.pack [fromIntegral (la `shiftR` 8), fromIntegral (la .&. 0xff)]
  | la < 2 ^ 32     = S.pack [0xff, 0xfe, bitfields la 24 31, bitfields la 16 23, bitfields la 8 15, bitfields la 0 7]
  | la < 2 ^ 64     = S.pack [0xff, 0xff, bitfields la 56 63, bitfields la 48 55, bitfields la 40 47, bitfields la 32 39, bitfields la 24 31, bitfields la 16 23, bitfields la 8 15, bitfields la 0 7]

encodeB0 m l nonce hasAdata lm = f <> nonce' <> lm'
  where l' = l - 1
        m' = (m - 2) `div` 2
        f  = S.singleton (encodeFlags hasAdata m' l')
        nonce' = S.take (15-l) (nonce <> S.replicate 16 0)
        lm' = S.drop (8 - l) (word64be lm)

encodeAdata adata
  | S.null adata = S.empty
  | r == 0 = t
  | r /= 0 = t <> S.replicate (16 - r) 0
  where la = fromIntegral (S.length adata)
        t = encodeLa la <> adata
        n = S.length t
        r = n `mod` 16

encodeM msg
  | r == 0 = msg
  | r /= 0 = msg <> S.replicate (16 - r) 0
  where lm = S.length msg
        r  = lm `mod` 16

encodeBlocks :: Int -> Int -> ByteString -> ByteString -> ByteString -> ByteString
encodeBlocks constM constL msg nonce adata =
  let b0 = encodeB0 constM constL nonce (not . S.null $ adata) (fromIntegral . S.length $ msg)
  in (b0 <> encodeAdata adata <> encodeM msg)

toBlocks s
  | S.null s = []
  | otherwise = S.take 16 s : toBlocks (S.drop 16 s)

xorBlocks :: ByteString -> ByteString -> ByteString
xorBlocks s t = S.pack $ S.zipWith xor s t

cbcmacBlocks :: BlockCipher cipher => cipher -> [ByteString] -> ByteString
cbcmacBlocks key (b0:bs) = foldl cbcMacXi x1 bs
  where
    x1 = ecbEncrypt key b0
    cbcMacXi xi bi = ecbEncrypt key (xorBlocks xi bi)

encodeCtr l nonce ctr = S.singleton (fromIntegral l') <> nonce' <> ctr'
  where l'     = l - 1
        nonce' = S.take (15-l) (nonce <> S.replicate 16 0)
        ctr'   = S.drop (8-l) (word64be ctr)

doCcmEncrypt :: forall cipher . BlockCipher cipher => Int -> Int -> cipher -> ByteString -> ByteString -> ByteString -> ByteString
doCcmEncrypt m l key msg nonce adata = encrypted <> u
  where
    ctrIv      = fromJust . makeIV $ encodeCtr l nonce 0
    s0         = ecbEncrypt key (BA.convert ctrIv)
    encrypted  = ctrCombine key (ivAdd ctrIv 1) msg
    bi@(b0:bs) = toBlocks $ encodeBlocks m l msg nonce adata
    t          = cbcmacBlocks key bi
    u          = S.take m $ xorBlocks t s0

-- |aes ccm encrypt, assuming M=16, L=2
-- Please note output doesn't prepend adata, user is expected to prepend adata instead.
-- i.e.: output' = adata <> output
ccmEncryptSimple :: forall cipher . BlockCipher cipher
                 => cipher                 -- ^block cipher
                 -> ByteString             -- ^message
                 -> ByteString             -- ^nonce (maximum size is 15 - L = 13, given L=2)
                 -> ByteString             -- ^adata
                 -> ByteString             -- ^output data: encrypted <> cbcmac
ccmEncryptSimple = ccmEncrypt 16 2

-- |aes ccm encrypt
-- Please note output doesn't prepend adata, user is expected to prepend adata instead.
-- i.e.: output' = adata <> output
ccmEncrypt :: forall cipher . BlockCipher cipher
                 => Int                    -- ^M value [4, 6 .. 16]
                 -> Int                    -- ^L value [2 .. 8]
                 -> cipher                 -- ^block cipher
                 -> ByteString             -- ^message
                 -> ByteString             -- ^nonce (maximum size is 15 - L = 13, given L=2)
                 -> ByteString             -- ^adata
                 -> ByteString             -- ^output data: encrypted <> cbcmac
ccmEncrypt = doCcmEncrypt
