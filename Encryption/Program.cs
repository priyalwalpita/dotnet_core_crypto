using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            string enc = Encrypt(Convert.FromBase64String(args[0]), args[1]);

            Console.WriteLine("Encrypted Message: " + enc);

            Console.Read();
        }

        public static  string Encrypt(byte[] pubKey, string txtToEncrypt)
        {
            RsaKeyParameters publicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(pubKey);

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = publicKey.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = publicKey.Exponent.ToByteArrayUnsigned();
            rsa.ImportParameters(rsaParameters);

            byte[] bytes = Encoding.UTF8.GetBytes(txtToEncrypt);
            byte[] enc = rsa.Encrypt(bytes, false);
            string base64Enc = Convert.ToBase64String(enc);

            return base64Enc;
        }
    }
}
