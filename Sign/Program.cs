using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Sign
{
    class Program
    {
        static void Main(string[] args)
        {
            string signedMsg = Sign(Convert.FromBase64String(args[0]), args[1]);
            Console.WriteLine("Signed Message :" + signedMsg);
        }

        static string Sign(byte[] pvtKey, string msgToSign)
        {
            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(pvtKey);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)privateKey);

            rsa.ImportParameters(rsaParameters);
            byte[] dataBytes = Encoding.UTF8.GetBytes(msgToSign);
            byte[] signedBytes = rsa.SignData(dataBytes, "SHA256");

            return Convert.ToBase64String(signedBytes);

        }
    }
}
