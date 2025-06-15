using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Formatters.Soap;
using System.Runtime.Serialization;
using System.Web.Script.Serialization;
using System.Xml.Serialization;
using System.Web.UI;
using Newtonsoft.Json;
using MessagePack;

namespace VulnerableDeserializationExamples
{
    public class VulnerableClass
    {
        // VULNERABLE: BinaryFormatter deserialization
        public object DeserializeBinary(byte[] data)
        {
            using (var stream = new MemoryStream(data))
            {
                var formatter = new BinaryFormatter(); // This line should be detected
                return formatter.Deserialize(stream); // This line should be detected
            }
        }

        // VULNERABLE: SoapFormatter deserialization
        public object DeserializeSoap(Stream stream)
        {
            var formatter = new SoapFormatter(); // This line should be detected
            return formatter.Deserialize(stream); // This line should be detected
        }

        // VULNERABLE: NetDataContractSerializer deserialization
        public object DeserializeNetDataContract(Stream stream, Type type)
        {
            var serializer = new NetDataContractSerializer(); // This line should be detected
            return serializer.Deserialize(stream); // This line should be detected
        }

        // VULNERABLE: JavaScriptSerializer deserialization
        public object DeserializeJavaScript(string json)
        {
            var serializer = new JavaScriptSerializer(); // This line should be detected
            return serializer.DeserializeObject(json); // This line should be detected
        }

        // VULNERABLE: Newtonsoft.Json with TypeNameHandling
        public T DeserializeWithTypeHandling<T>(string json)
        {
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All // This line should be detected
            };
            return JsonConvert.DeserializeObject<T>(json, settings);
        }

        // VULNERABLE: Newtonsoft.Json with TypeNameHandling (different variations)
        public object DeserializeWithTypeHandlingObjects(string json)
        {
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Objects // This line should be detected
            };
            return JsonConvert.DeserializeObject(json, settings); // This should also be detected (no type specified)
        }

        // VULNERABLE: XmlSerializer with potentially untrusted data
        public T DeserializeXml<T>(Stream stream)
        {
            var serializer = new XmlSerializer(typeof(T)); // This line should be detected
            return (T)serializer.Deserialize(stream); // This line should be detected
        }

        // VULNERABLE: LosFormatter deserialization
        public object DeserializeLos(string data)
        {
            var formatter = new LosFormatter(); // This line should be detected
            return formatter.Deserialize(data); // This line should be detected
        }

        // VULNERABLE: ObjectStateFormatter deserialization
        public object DeserializeObjectState(string data)
        {
            var formatter = new ObjectStateFormatter(); // This line should be detected
            return formatter.Deserialize(data); // This line should be detected
        }

        // VULNERABLE: JsonConvert.DeserializeObject without type specification
        public object DeserializeJsonUnsafe(string json)
        {
            return JsonConvert.DeserializeObject(json); // This line should be detected
        }

        // VULNERABLE: JsonConvert.DeserializeObject with settings but no type
        public object DeserializeJsonUnsafeWithSettings(string json)
        {
            var settings = new JsonSerializerSettings();
            return JsonConvert.DeserializeObject(json, settings); // This line should be detected
        }

        // VULNERABLE: MessagePack deserialization (potentially unsafe)
        public T DeserializeMessagePack<T>(byte[] data)
        {
            return MessagePackSerializer.Deserialize<T>(data); // This line should be detected
        }

        // VULNERABLE: MessagePack deserialization without type
        public object DeserializeMessagePackUnsafe(byte[] data)
        {
            return MessagePackSerializer.Deserialize(data); // This line should be detected
        }

        // More complex scenarios that should still be detected
        public void ComplexVulnerableScenarios()
        {
            // Inline BinaryFormatter usage
            var obj1 = new BinaryFormatter().Deserialize(new MemoryStream()); // Should be detected

            // With variable assignment
            BinaryFormatter bf = new BinaryFormatter();
            var obj2 = bf.Deserialize(new MemoryStream()); // Should be detected

            // Chained calls
            var data = File.ReadAllBytes("test.bin");
            var result = new BinaryFormatter().Deserialize(new MemoryStream(data)); // Should be detected

            // TypeNameHandling in different contexts
            JsonConvert.DeserializeObject<object>("", new JsonSerializerSettings 
            { 
                TypeNameHandling = TypeNameHandling.Auto // Should be detected
            });
        }

        // Example of what attackers might exploit
        public void ExampleAttack()
        {
            // This demonstrates why these are dangerous:
            // An attacker could craft malicious serialized data that when deserialized
            // executes arbitrary code through gadget chains
            string maliciousPayload = GetMaliciousSerializedData();
            
            // VULNERABLE: This could execute malicious code
            var formatter = new BinaryFormatter();
            var maliciousObject = formatter.Deserialize(new MemoryStream(Convert.FromBase64String(maliciousPayload)));
        }

        private string GetMaliciousSerializedData()
        {
            // This would contain a malicious payload in real attacks
            return "base64encodedmaliciouspayload";
        }
    }

    // Supporting classes for the examples
    [Serializable]
    public class SampleData
    {
        public string Name { get; set; }
        public int Value { get; set; }
    }

    [MessagePackObject]
    public class MessagePackData
    {
        [Key(0)]
        public string Data { get; set; }
    }
}
