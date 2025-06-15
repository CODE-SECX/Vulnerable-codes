using System;
using System.IO;
using System.Web;

namespace VulnerablePathTraversalExamples
{
    public class PathTraversalVulnerabilities
    {
        // Example 1: File.ReadAllText with user input (VULNERABLE)
        public string ReadFileContent(string fileName)
        {
            // This should be detected by rule 1
            string content = File.ReadAllText(Request.QueryString["file"]);
            return content;
        }

        // Example 2: File.ReadAllBytes with user input (VULNERABLE)
        public byte[] ReadFileBytes(string fileName)
        {
            // This should be detected by rule 2
            byte[] data = File.ReadAllBytes(Request.QueryString["filename"]);
            return data;
        }

        // Example 3: File.WriteAllText with user input (VULNERABLE)
        public void WriteToFile(string content)
        {
            // This should be detected by rule 3
            File.WriteAllText(Request.QueryString["outputfile"], content);
        }

        // Example 4: FileStream with user input (VULNERABLE)
        public void ProcessFile()
        {
            // This should be detected by rule 4
            using (var fs = new FileStream(Request.QueryString["path"], FileMode.Open))
            {
                // Process file
            }
        }

        // Example 5: Directory.GetFiles with user input (VULNERABLE)
        public string[] ListFiles()
        {
            // This should be detected by rule 5
            return Directory.GetFiles(Request.QueryString["directory"]);
        }

        // Example 6: Path.Combine with user input (VULNERABLE)
        public string BuildPath()
        {
            // This should be detected by rule 6
            string path = Path.Combine(@"C:\uploads\", Request.QueryString["filename"]);
            return path;
        }

        // Example 7: File.Open with user input (VULNERABLE)
        public void OpenFile()
        {
            // This should be detected by rule 7
            using (var file = File.Open(Request.QueryString["file"], FileMode.Open))
            {
                // Process file
            }
        }

        // Example 8: File.Delete with user input (VULNERABLE)
        public void DeleteFile()
        {
            // This should be detected by rule 8
            File.Delete(Request.QueryString["fileToDelete"]);
        }

        // Example 9: StreamReader with user input (VULNERABLE)
        public string ReadWithStreamReader()
        {
            // This should be detected by rule 9
            using (var reader = new StreamReader(Request.QueryString["textfile"]))
            {
                return reader.ReadToEnd();
            }
        }

        // Example 10: DirectoryInfo with user input (VULNERABLE)
        public DirectoryInfo GetDirectoryInfo()
        {
            // This should be detected by rule 10
            return new DirectoryInfo(Request.QueryString["dir"]);
        }

        // Example 11: FileInfo with user input (VULNERABLE)
        public FileInfo GetFileInfo()
        {
            // This should be detected by rule 11
            return new FileInfo(Request.QueryString["filepath"]);
        }

        // Example 12: Console input vulnerability (VULNERABLE)
        public void ProcessUserInput()
        {
            Console.WriteLine("Enter filename:");
            string userInput = Console.ReadLine();
            
            // These should be detected by various rules
            string content = File.ReadAllText(userInput);
            File.WriteAllText(userInput + ".bak", content);
            
            using (var fs = new FileStream(userInput, FileMode.Open))
            {
                // Process
            }
        }

        // Example 13: Method parameter vulnerability (VULNERABLE)
        public void ProcessFileParameter(string userFileName)
        {
            // These should be detected as userFileName could be user input
            string data = File.ReadAllText(userFileName);
            File.WriteAllText(userFileName + ".processed", data);
        }

        // Example 14: Command line arguments vulnerability (VULNERABLE)
        public static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                // This should be detected by rules as args[0] is user input
                string content = File.ReadAllText(args[0]);
                Console.WriteLine(content);
                
                // Multiple vulnerabilities in one line
                File.WriteAllText(args[1], File.ReadAllText(args[0]));
            }
        }

        // Example 15: Web API vulnerability (VULNERABLE)
        public string GetFile(string filename)
        {
            // Simulating web API input
            string userInput = filename; // This represents user input from API
            
            // Multiple path traversal vulnerabilities
            var fileInfo = new FileInfo(userInput);
            if (fileInfo.Exists)
            {
                return File.ReadAllText(userInput);
            }
            return string.Empty;
        }

        // Example 16: Complex path building vulnerability (VULNERABLE)
        public void ComplexPathOperation()
        {
            string baseDir = @"C:\app\files\";
            string userDir = Request.QueryString["subdir"];
            string fileName = Request.QueryString["filename"];
            
            // This shows how Path.Combine can still be vulnerable
            string fullPath = Path.Combine(baseDir, userDir, fileName);
            
            // Multiple operations on the same vulnerable path
            if (File.Exists(fullPath))
            {
                string content = File.ReadAllText(fullPath);
                File.WriteAllText(fullPath + ".backup", content);
                File.Delete(fullPath);
            }
        }
    }

    // Additional class with more vulnerabilities
    public class FileUploadHandler
    {
        public void SaveUploadedFile(HttpPostedFile file)
        {
            // Vulnerable file save operation
            string fileName = Request.QueryString["targetname"];
            file.SaveAs(fileName); // This won't be caught by our rules but is also vulnerable
            
            // Additional vulnerable operations
            var info = new FileInfo(fileName);
            if (info.Exists)
            {
                byte[] data = File.ReadAllBytes(fileName);
                // Process data
            }
        }
    }
}
