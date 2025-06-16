using System;
using System.IO;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;
using System.Xml.XPath;
using System.Xml.Xsl;

namespace VulnerableXmlExamples
{
    public class XmlVulnerabilities
    {
        // VULNERABLE: XmlDocument without secure settings
        public void VulnerableXmlDocument1()
        {
            XmlDocument doc = new XmlDocument(); // Should be detected by rule 1
            doc.LoadXml("<root>test</root>");
        }

        // VULNERABLE: XmlDocument with load from file
        public void VulnerableXmlDocument2(string fileName)
        {
            XmlDocument xmlDoc = new XmlDocument(); // Should be detected by rule 1
            xmlDoc.Load(fileName);
        }

        // VULNERABLE: XmlReader.Create without secure settings
        public void VulnerableXmlReader1(Stream stream)
        {
            XmlReader reader = XmlReader.Create(stream); // Should be detected by rule 2
            // Process XML
        }

        // VULNERABLE: XmlReader.Create with partial settings
        public void VulnerableXmlReader2(string fileName)
        {
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.IgnoreWhitespace = true;
            XmlReader reader = XmlReader.Create(fileName, settings); // Should be detected by rule 2
        }

        // VULNERABLE: XmlTextReader usage
        public void VulnerableXmlTextReader(Stream stream)
        {
            XmlTextReader reader = new XmlTextReader(stream); // Should be detected by rule 3
            while (reader.Read())
            {
                // Process nodes
            }
        }

        // VULNERABLE: XmlTextReader with string input
        public void VulnerableXmlTextReader2(string xmlString)
        {
            XmlTextReader reader = new XmlTextReader(new StringReader(xmlString)); // Should be detected by rule 3
        }

        // VULNERABLE: XmlReaderSettings without MaxCharactersInDocument
        public void VulnerableXmlReaderSettings()
        {
            XmlReaderSettings settings = new XmlReaderSettings(); // Should be detected by rule 4
            settings.DtdProcessing = DtdProcessing.Prohibit;
            // Missing MaxCharactersInDocument
        }

        // VULNERABLE: XML Deserialization without secure reader
        public T VulnerableDeserialization<T>(Stream stream)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(T));
            return (T)serializer.Deserialize(stream); // Should be detected by rule 5
        }

        // VULNERABLE: XML Deserialization with TextReader
        public object VulnerableDeserialization2(string xmlData)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(object));
            StringReader stringReader = new StringReader(xmlData);
            return serializer.Deserialize(stringReader); // Should be detected by rule 5
        }

        // VULNERABLE: XPathDocument without secure settings
        public void VulnerableXPathDocument(string fileName)
        {
            XPathDocument doc = new XPathDocument(fileName); // Should be detected by rule 6
        }

        // VULNERABLE: XPathDocument with stream
        public void VulnerableXPathDocument2(Stream stream)
        {
            XPathDocument document = new XPathDocument(stream); // Should be detected by rule 6
        }

        // VULNERABLE: XmlSchemaSet without secure resolver
        public void VulnerableXmlSchemaSet()
        {
            XmlSchemaSet schemaSet = new XmlSchemaSet(); // Should be detected by rule 7
            schemaSet.Add("http://example.com/schema", "schema.xsd");
        }

        // VULNERABLE: XSLT Transform without secure settings
        public void VulnerableXsltTransform(string inputXml, string stylesheetFile, string outputFile)
        {
            XslCompiledTransform xslt = new XslCompiledTransform();
            xslt.Load(stylesheetFile);
            xslt.Transform(inputXml, outputFile); // Should be detected by rule 8
        }

        // VULNERABLE: Complex XSLT scenario
        public void VulnerableXsltTransform2(XmlReader input, XmlWriter output)
        {
            XslCompiledTransform transform = new XslCompiledTransform();
            transform.Load("stylesheet.xsl");
            transform.Transform(input, output); // Should be detected by rule 8
        }

        // Example of XXE payload that could be exploited
        public void ProcessUserXml(string userXml)
        {
            // This is what an attacker might try to inject:
            string xxePayload = @"<?xml version='1.0'?>
                <!DOCTYPE root [
                    <!ENTITY xxe SYSTEM 'file:///etc/passwd'>
                ]>
                <root>&xxe;</root>";

            XmlDocument doc = new XmlDocument(); // VULNERABLE
            doc.LoadXml(userXml); // Could load the XXE payload above
        }

        // XML Bomb example
        public void ProcessXmlBomb()
        {
            string xmlBomb = @"<?xml version='1.0'?>
                <!DOCTYPE lolz [
                    <!ENTITY lol 'lol'>
                    <!ENTITY lol2 '&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;'>
                    <!ENTITY lol3 '&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;'>
                    <!ENTITY lol4 '&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;'>
                ]>
                <lolz>&lol4;</lolz>";

            XmlReaderSettings settings = new XmlReaderSettings(); // VULNERABLE - no limits
            XmlReader reader = XmlReader.Create(new StringReader(xmlBomb), settings);
        }
    }

    // Additional vulnerable patterns
    public class MoreVulnerablePatterns
    {
        // Multiple vulnerabilities in one method
        public void MultipleVulnerabilities(string fileName)
        {
            // Vulnerable XmlDocument
            XmlDocument doc1 = new XmlDocument();
            
            // Vulnerable XmlTextReader
            XmlTextReader reader1 = new XmlTextReader(fileName);
            
            // Vulnerable XmlReader
            XmlReader reader2 = XmlReader.Create(fileName);
            
            // Vulnerable deserialization
            XmlSerializer serializer = new XmlSerializer(typeof(string));
            using (FileStream fs = new FileStream(fileName, FileMode.Open))
            {
                serializer.Deserialize(fs);
            }
        }

        // Vulnerable XML processing in a loop
        public void ProcessMultipleXmlFiles(string[] fileNames)
        {
            foreach (string fileName in fileNames)
            {
                XmlDocument xmlDocument = new XmlDocument(); // Repeated vulnerability
                xmlDocument.Load(fileName);
            }
        }
    }
}
