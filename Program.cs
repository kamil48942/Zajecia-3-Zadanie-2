using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        SymmetricAlgorithm[] algorithms = new SymmetricAlgorithm[]
        {
            new AesCryptoServiceProvider { KeySize = 128 },
            new AesCryptoServiceProvider { KeySize = 256 },
            new AesManaged { KeySize = 128 },
            new AesManaged { KeySize = 256 },
            new RijndaelManaged { KeySize = 128 },
            new RijndaelManaged { KeySize = 256 },
            new DESCryptoServiceProvider(),
            new TripleDESCryptoServiceProvider()
        };

        int dataSize = 1024 * 1024; 
        byte[] data = new byte[dataSize];
        new Random().NextBytes(data);

        Console.WriteLine("Algorytm\tSekund/Blok\tBajtów/sek (RAM)\tBajtów/sek (HDD)");

        foreach (var algorithm in algorithms)
        {
            algorithm.GenerateKey();
            algorithm.GenerateIV();

            var ramEncryptTime = MeasureTime(() => EncryptData(algorithm, data));
            var ramDecryptTime = MeasureTime(() => DecryptData(algorithm, EncryptData(algorithm, data)));

            var hddEncryptTime = MeasureTime(() => EncryptDataFromFile(algorithm, "data.bin", "encrypted.bin"));
            var hddDecryptTime = MeasureTime(() => DecryptDataFromFile(algorithm, "encrypted.bin", "decrypted.bin"));

            double blockTime = (ramEncryptTime + ramDecryptTime) / 2.0;
            double bytesPerSecondRam = dataSize / ((ramEncryptTime + ramDecryptTime) / 2.0);
            double bytesPerSecondHdd = dataSize / ((hddEncryptTime + hddDecryptTime) / 2.0);

            Console.WriteLine($"{algorithm.GetType().Name} ({algorithm.KeySize} bit)\t{blockTime:F6}\t{bytesPerSecondRam:F2}\t{bytesPerSecondHdd:F2}");
        }
    }

    static long MeasureTime(Action action)
    {
        var stopwatch = Stopwatch.StartNew();
        action();
        stopwatch.Stop();
        return stopwatch.ElapsedMilliseconds;
    }

    static byte[] EncryptData(SymmetricAlgorithm algorithm, byte[] data)
    {
        using (var encryptor = algorithm.CreateEncryptor(algorithm.Key, algorithm.IV))
        using (var ms = new MemoryStream())
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }
    }

    static byte[] DecryptData(SymmetricAlgorithm algorithm, byte[] data)
    {
        using (var decryptor = algorithm.CreateDecryptor(algorithm.Key, algorithm.IV))
        using (var ms = new MemoryStream(data))
        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
        using (var result = new MemoryStream())
        {
            cs.CopyTo(result);
            return result.ToArray();
        }
    }

    static void EncryptDataFromFile(SymmetricAlgorithm algorithm, string inputFile, string outputFile)
    {
        using (var encryptor = algorithm.CreateEncryptor(algorithm.Key, algorithm.IV))
        using (var inputStream = new FileStream(inputFile, FileMode.Open))
        using (var outputStream = new FileStream(outputFile, FileMode.Create))
        using (var cs = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
        {
            inputStream.CopyTo(cs);
        }
    }

    static void DecryptDataFromFile(SymmetricAlgorithm algorithm, string inputFile, string outputFile)
    {
        using (var decryptor = algorithm.CreateDecryptor(algorithm.Key, algorithm.IV))
        using (var inputStream = new FileStream(inputFile, FileMode.Open))
        using (var outputStream = new FileStream(outputFile, FileMode.Create))
        using (var cs = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
        {
            cs.CopyTo(outputStream);
        }
    }
}
