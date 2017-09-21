using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Decryption
{
    class Program
    {
        static void Main(string[] args)
        {
            string decryptedMsg = Decrypt(Convert.FromBase64String(args[0]), args[1]);
            Console.WriteLine("Decrypted Msg: " + decryptedMsg);
        }

        public static string Decrypt(byte[] pvtKey, string txtToDecrypt)
        {
            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(pvtKey);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            RSAParameters rsaParameters = new RSAParameters();

            RSAParameters rsaParameters2 = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)privateKey);

            rsa.ImportParameters(rsaParameters2);

            byte[] dec = rsa.Decrypt(Convert.FromBase64String(txtToDecrypt), false);
            string decStr = Encoding.UTF8.GetString(dec);

            return decStr;
        }
    }
}
