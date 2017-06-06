{-# LANGUAGE GADTs, DataKinds, KindSignatures, FlexibleInstances #-}
module Data.Password
  ( Password
  , AnyPassword (..)
  , PasswordType (..)
  , fromPlainText
  , hash
  ) where
import Data.ByteString (ByteString)
import Data.Text
import Crypto.KDF.PBKDF2
import Crypto.Random.Entropy
import Crypto.Hash.Algorithms
import Data.Text.Encoding
import Data.Aeson
import Database.PostgreSQL.Simple.ToField
import Database.PostgreSQL.Simple.FromField

data PasswordType = Hashed | PlainText

data Password :: PasswordType -> * where
  PPlainText :: Text       -> Password 'PlainText
  PHashed    :: ByteString -> Password 'Hashed

instance Eq (Password 'Hashed) where
  PHashed x == PHashed y = x == y

data AnyPassword where
  AnyPassword :: Password a -> AnyPassword

hash :: Password a -> IO (Password 'Hashed)
hash (PHashed    x) = return $ PHashed x
hash (PPlainText x) = do
  salt <- getEntropy 64 :: IO ByteString
  let params = Parameters
               { iterCounts   = 10000
               , outputLength = 64
               }
  return $ PHashed $ generate (prfHMAC SHA512) params (encodeUtf8 x) salt

fromPlainText :: Text -> Password 'PlainText
fromPlainText = PPlainText

instance FromJSON (Password 'PlainText) where
  parseJSON = withText "Password PlainText" $ pure . fromPlainText

instance ToField (Password 'Hashed) where
  toField (PHashed x) = toField x

instance FromField (Password 'Hashed) where
  fromField x y = PHashed <$> fromField x y
