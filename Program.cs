using System.Reflection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace bm3soft.data.protector;

internal class Program
{
    static DataProtectorConfig  dpConfig   = new DataProtectorConfig();
    static void Main(string[] args)
    {
        if (args.Length < 3)
        {
            var versionString = Assembly.GetEntryAssembly()?
                                    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                                    .InformationalVersion
                                    .ToString();

            Console.WriteLine($"data-protector v{versionString}");
            Console.WriteLine("-------------");
            Console.WriteLine("\nUsage:");
            Console.WriteLine("  data-protector [operation mode = 'E' for Encryption or 'D' for Decryption ] [namespace] [plaintext/ciphertext] [silence flag 'true' if you want to silence mode]");
            return;
        }
        

        IConfiguration configuration = new ConfigurationBuilder()
       .AddJsonFile($"{Directory.GetCurrentDirectory()}/dp.json", true,false)
       .Build();

        var dpConfigSection = configuration.GetSection(nameof(DataProtectorConfig));      
        dpConfig.KeyOutputLocation = dpConfigSection["KeyOutputLocation"];
        dpConfig.ApplicationName = dpConfigSection["ApplicationName"];
               

        var operationMode =args[0]; 
        if (String.IsNullOrEmpty(operationMode )) {
            Console.WriteLine("ERROR: You need to specify a operation Mode!");
            return; 
        }

        var nspace_value = args[1];  
        if (String.IsNullOrEmpty(nspace_value )) {
            Console.WriteLine("ERROR: You need to specify a namespace!");
            return; 
        }

        var inputValue = args[2];
        if (String.IsNullOrEmpty(inputValue)) {
            Console.WriteLine("ERROR: You need to specify a input value (plaintext or ciphertext)!");
            return; 
        }

        var silenceFlag = false;

        if ( args.Length > 3)
            silenceFlag = Convert.ToBoolean(args[3]);

        MainLogic("Welcome to Data-Protector!", nspace_value, inputValue, silenceFlag, operationMode);

        
    }

    static void MainLogic(string message, string nspace, string inputValue, bool silenceFlag, string operationMode  )
{
    string logo = $"\n        \t{message}";
    logo += @"
        ........................................
        ........................................
        ........................................
        ...............WWNNNNNNWW...............
        .............WNXNNWWWWNNXNW.............
        .............NXN........NXN.............
        ............WXXW........WXXW............
        ............WXNW........WNNW............
        ............NXXNNNNWWWNNNNNW............
        ...........WKOkkOOOOOOOOOOOKW...........
        ...........N0kxxxxdoodxxxkk0W...........
        ...........N0kxxxx:..;dxxkk0W...........
        ...........N0kxxxx:..,dxxkk0N...........
        ...........N0kxxxxl;,:dxxkk0N...........
        ...........WX0OOOOOOOOOOOO0XW...........
        ............WWWWWWWWWWWWWWWW............
        ........................................
        ........................................
        ........................................
        ........................................
        ";

    if (!silenceFlag)
        Console.WriteLine(logo);

    var serviceCollection = new ServiceCollection();
    var dpservice = serviceCollection.AddDataProtection();
    if (!String.IsNullOrEmpty(dpConfig.KeyOutputLocation))    {
        dpservice.PersistKeysToFileSystem(new DirectoryInfo(dpConfig.KeyOutputLocation));
    }

    if (!String.IsNullOrEmpty(dpConfig.ApplicationName)) {
        dpservice.SetApplicationName(dpConfig.ApplicationName);
    }

    var services = serviceCollection.BuildServiceProvider();
    
    var instance = ActivatorUtilities.CreateInstance<ProtectionManager>(services, nspace); 
    switch (operationMode.ToLower() ) {
        case "e":
            instance.Encrypt(inputValue);
        break;
        case "d":
            instance.Decrypt(inputValue);
        break;
        default:
            Console.WriteLine("please provide correct operation mode 'E' or 'D'");
        break;
    }



}

 public class ProtectionManager
    {
        IDataProtector _protector;

        // the 'provider' parameter is provided by DI
        public ProtectionManager(IDataProtectionProvider provider, string nspace)
        {
            _protector = provider.CreateProtector(nspace);
        }


/*
        public void RunSample()
        {
            Console.Write("Enter input: ");
            string input = Console.ReadLine();

            // protect the payload
            string protectedPayload = _protector.Protect(input);
            Console.WriteLine($"Protect returned: {protectedPayload}");

            // unprotect the payload
            string unprotectedPayload = _protector.Unprotect(protectedPayload);
            Console.WriteLine($"Unprotect returned: {unprotectedPayload}");
        }
*/

        internal void Encrypt(string plaintext)
        {
            if ( String.IsNullOrEmpty(plaintext) ) throw new ArgumentException("plaintext cannot be null");            
            string protectedPayload = _protector.Protect(plaintext);
            Console.WriteLine($"{protectedPayload}");
        }

        internal void Decrypt(string ciphertext)
        {
            if ( String.IsNullOrEmpty(ciphertext) ) throw new ArgumentException("ciphertext cannot be null");            
            string plaintext = "";
            
            try{
                 plaintext = _protector.Unprotect(ciphertext);
            }catch (System.Security.Cryptography.CryptographicException) {

            }

            Console.WriteLine($"{plaintext}");
        }
    }

}