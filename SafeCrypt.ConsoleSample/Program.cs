using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SafeCrypt;

namespace SafeCrypt.ConsoleSample
{
    class Program
    {
        static void Main(string[] args)
        {
            var EncryptionKey = "1AE7AF71D4EB4F382226D3E36441934CBF27DD437720135E287B554BDDDC85A2";
            var ValidationKey = "9FA1F8EA0EA0375E51562E30AEBB78C55A8AC7CE3B15260232D5A7DEDD3B6314";

            var token = "tlb,Troels Liebe Bentsen";

            var sc = new SafeCrypt(EncryptionKey, ValidationKey);

            var ectoken = sc.Encode(Encoding.UTF8.GetBytes(token));

            Console.WriteLine(ectoken);
            Console.WriteLine(Encoding.UTF8.GetString(sc.Decode(ectoken)));
            
            Console.ReadKey();
        }
    }
}
