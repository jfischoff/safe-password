module Data.PlainText
  ( PlainText
  , fromText
  , hash
  ) where
import Data.ByteString (ByteString)
import Data.Text
import Crypto.KDF.PBKDF2
import Crypto.Random.Entropy
import Crypto.Hash.Algorithms
import Data.Text.Encoding
import Data.Aeson

data PlainText = PlainText Text

fromText :: Text -> PlainText
fromText = PlainText

hash :: PlainText -> IO ByteString
hash (PlainText x) = do
  salt <- getEntropy 64 :: IO ByteString
  let params = Parameters
               { iterCounts   = 10000
               , outputLength = 64
               }
  return $ generate (prfHMAC SHA512) params (encodeUtf8 x) salt

instance FromJSON PlainText where
  parseJSON = withText "Password PlainText" $ pure . fromText
