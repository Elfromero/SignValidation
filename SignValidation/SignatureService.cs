using System;
using System.Diagnostics;
using System.IO;
using System.IO.Abstractions;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Qognify.Export.Advanced.Contract.Export.Interfaces;

public class SignatureService : ISignatureService
{
    private static readonly log4net.ILog LOGGER = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
    private readonly X509Certificate2 cert;
    private readonly IFileSystem fileSystem;

    public SignatureService(IFileSystem fileSystem = null)
    {
        this.fileSystem = fileSystem ?? new FileSystem();
        cert = LoadEmbeddedCertificate(Constants.CERT_FILE_NAME);
    }

    public byte[] GenerateSignature(string filePath)
    {
        if (!fileSystem.File.Exists(filePath))
        {
            throw new ArgumentException($"File {filePath} not existing!");
        }

        byte[] signature;
        var sw = new Stopwatch();
        sw.Start();
        using (var fileStream = fileSystem.File.OpenRead(filePath))
        {
            using (var stream = new BufferedStream(fileStream))
            {
                using (var ecdsa = cert.GetECDsaPrivateKey())
                {
                    signature = ecdsa.SignData(stream, HashAlgorithmName.SHA512);
                }
            }
        }

        sw.Stop();
        LOGGER.Info($"Generating signature for '{filePath}' took {sw.ElapsedMilliseconds}ms.");

        return signature;
    }

    private X509Certificate2 LoadEmbeddedCertificate(string embeddedCertFileName)
    {
        X509Certificate2 certificate;
        var assembly = Assembly.GetExecutingAssembly();
        var certPath = assembly.GetManifestResourceNames().FirstOrDefault(rn => rn.Contains(embeddedCertFileName));
        if (certPath == null)
        {
            throw new Exception("No embedded certificate found!");
        }

        using (var stream = assembly.GetManifestResourceStream(certPath))
        {
            if (stream == null) throw new Exception("Loading certificate failed!");

            var raw = new byte[stream.Length];

            for (var i = 0; i < stream.Length; ++i)
                raw[i] = (byte)stream.ReadByte();

            certificate = new X509Certificate2();
            certificate.Import(raw, Constants.CERT_TOKEN, X509KeyStorageFlags.UserKeySet);
        }

        return certificate;
    }

    public bool VerifySignature(string fileToVerify, string signFile)
    {
        var signatureFile = fileSystem.File.ReadAllBytes(signFile);

        using (var fileStream = fileSystem.File.OpenRead(fileToVerify))
        {
            using (var stream = new BufferedStream(fileStream))
            {
                using (var ecdsa = cert.GetECDsaPublicKey())
                {
                    return ecdsa.VerifyData(stream, signatureFile, HashAlgorithmName.SHA512);
                }
            }
        }
    }
    
    public bool VerifySignature(string fileToVerifyPath, byte[] signature)
    {
        using (var fileStream = fileSystem.File.OpenRead(fileToVerifyPath))
        {
            using (var stream = new BufferedStream(fileStream))
            {
                using (var ecdsa = cert.GetECDsaPublicKey())
                {
                    return ecdsa.VerifyData(stream, signature, HashAlgorithmName.SHA512);
                }
            }
        }
    }
}