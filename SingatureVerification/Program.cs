using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace SingatureVerification
{
    class Program
    {
        static void Main(string[] args)
        {
            bool verified = Verify(Convert.FromBase64String(args[0]), args[1], args[2]);
            Console.WriteLine("Signature Verified" + verified);
        }

        public static  bool Verify(byte[] pubKey, string originalMessage, string signedMessage)
        {


            RsaKeyParameters publicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(pubKey);

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = publicKey.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = publicKey.Exponent.ToByteArrayUnsigned();
            rsa.ImportParameters(rsaParameters);

            byte[] bytesToVerify = Convert.FromBase64String(originalMessage);
            byte[] signedBytes = Convert.FromBase64String(signedMessage);


            bool success = rsa.VerifyData(bytesToVerify, CryptoConfig.MapNameToOID("SHA256"), signedBytes);

            return success;
        }
    }
}
