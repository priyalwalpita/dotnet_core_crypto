using System;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace KeyGenerator
{
    class Program
    {
        static void Main(string[] args)
        {
            var keys = GenerateKeys(2048);

            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keys.Private);
            byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetDerEncoded();

            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keys.Public);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();

            Console.WriteLine("Pvt Key :" + Convert.ToBase64String(serializedPrivateBytes));
            Console.WriteLine("Pub Key :" + Convert.ToBase64String(serializedPublicBytes));

            Console.Read();
        }

        private static AsymmetricCipherKeyPair GenerateKeys(int keySizeInBits)
        {
            var r = new RsaKeyPairGenerator();
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            r.Init(new KeyGenerationParameters(new SecureRandom(randomGenerator), keySizeInBits));
            var keys = r.GenerateKeyPair();
            return keys;
        }
    }
}
