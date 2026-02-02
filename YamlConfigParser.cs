using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Befree
{
    public class YamlConfigParser
    {
        public static List<Node> ParseYamlFile(string filePath, ref int totalVmessCount, ref int totalSsCount, ref int totalTrojanCount, ref int totalHysteria2Count)
        {
            var nodes = new List<Node>();

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"[-] 文件不存在：{filePath}");
                return nodes;
            }

            try
            {
                string yamlContent = File.ReadAllText(filePath, Encoding.UTF8);

                var deserializer = new DeserializerBuilder()
                    .WithNamingConvention(UnderscoredNamingConvention.Instance)
                    .Build();

                var yamlData = deserializer.Deserialize<Dictionary<string, object>>(yamlContent);

                if (yamlData == null || !yamlData.ContainsKey("proxies"))
                {
                    Console.WriteLine($"[-] 文件中没有找到 proxies 节点：{filePath}");
                    return nodes;
                }

                var proxies = yamlData["proxies"] as List<object>;

                if (proxies == null)
                {
                    Console.WriteLine($"[-] proxies 格式错误：{filePath}");
                    return nodes;
                }

                Console.WriteLine($" [+] 从 {filePath} 中找到 {proxies.Count} 个节点");

                foreach (var proxy in proxies)
                {
                    Node node = ParseProxy(proxy);
                    if (node != null)
                    {
                        nodes.Add(node);
                        if (node is VmessNode) totalVmessCount++;
                        else if (node is ShadowsocksNode) totalSsCount++;
                        else if (node is TrojanNode) totalTrojanCount++;
                        else if (node is Hysteria2Node) totalHysteria2Count++;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] 解析 YAML 文件 {filePath} 时出错：{ex.Message}");
            }

            return nodes;
        }

        private static Node ParseProxy(object proxyData)
        {
            if (proxyData == null) return null;

            var proxyDict = proxyData as Dictionary<object, object>;
            if (proxyDict == null) return null;

            // 转换键为字符串
            var dict = new Dictionary<string, object>();
            foreach (var kvp in proxyDict)
            {
                dict[kvp.Key?.ToString()?.ToLower() ?? ""] = kvp.Value;
            }

            if (!dict.ContainsKey("type")) return null;
            string type = dict["type"]?.ToString()?.ToLower() ?? "";

            switch (type)
            {
                case "ss":
                case "shadowsocks":
                    return ParseShadowsocks(dict);
                case "vmess":
                    return ParseVmess(dict);
                case "trojan":
                    return ParseTrojan(dict);
                case "hysteria2":
                case "hy2":
                    return ParseHysteria2(dict);
                case "vless":
                    return ParseVless(dict);
                default:
                    Console.WriteLine($"[-] 暂不支持的协议类型：{type}");
                    return null;
            }
        }

        private static ShadowsocksNode ParseShadowsocks(Dictionary<string, object> dict)
        {
            try
            {
                return new ShadowsocksNode
                {
                    Name = dict.ContainsKey("name") ? dict["name"].ToString() : "未知SS",
                    Server = dict.ContainsKey("server") ? dict["server"].ToString() : "",
                    Port = dict.ContainsKey("port") ? Convert.ToInt32(dict["port"]) : 8388,
                    Cipher = dict.ContainsKey("cipher") ? dict["cipher"].ToString() : "aes-256-gcm",
                    Password = dict.ContainsKey("password") ? dict["password"].ToString() : ""
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] 解析 SS 节点失败：{ex.Message}");
                return null;
            }
        }

        private static VmessNode ParseVmess(Dictionary<string, object> dict)
        {
            try
            {
                return new VmessNode
                {
                    Name = dict.ContainsKey("name") ? dict["name"].ToString() : "未知Vmess",
                    Server = dict.ContainsKey("server") ? dict["server"].ToString() : "",
                    Port = dict.ContainsKey("port") ? Convert.ToInt32(dict["port"]) : 443,
                    UUID = dict.ContainsKey("uuid") ? dict["uuid"].ToString() : "",
                    Cipher = dict.ContainsKey("cipher") ? dict["cipher"].ToString() : "auto"
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] 解析 Vmess 节点失败：{ex.Message}");
                return null;
            }
        }

        private static TrojanNode ParseTrojan(Dictionary<string, object> dict)
        {
            try
            {
                return new TrojanNode
                {
                    Name = dict.ContainsKey("name") ? dict["name"].ToString() : "未知Trojan",
                    Server = dict.ContainsKey("server") ? dict["server"].ToString() : "",
                    Port = dict.ContainsKey("port") ? Convert.ToInt32(dict["port"]) : 443,
                    Password = dict.ContainsKey("password") ? dict["password"].ToString() : "",
                    Sni = dict.ContainsKey("sni") ? dict["sni"].ToString() : ""
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] 解析 Trojan 节点失败：{ex.Message}");
                return null;
            }
        }

        private static Hysteria2Node ParseHysteria2(Dictionary<string, object> dict)
        {
            try
            {
                return new Hysteria2Node
                {
                    Name = dict.ContainsKey("name") ? dict["name"].ToString() : "未知Hysteria2",
                    Server = dict.ContainsKey("server") ? dict["server"].ToString() : "",
                    Port = dict.ContainsKey("port") ? Convert.ToInt32(dict["port"]) : 443,
                    Password = dict.ContainsKey("password") ? dict["password"].ToString() : "",
                    Sni = dict.ContainsKey("sni") ? dict["sni"].ToString() : "",
                    SkipCertVerify = dict.ContainsKey("skip-cert-verify") &&
                                   (dict["skip-cert-verify"].ToString().ToLower() == "true" ||
                                    dict["skip-cert-verify"].ToString() == "1")
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] 解析 Hysteria2 节点失败：{ex.Message}");
                return null;
            }
        }

        private static Node ParseVless(Dictionary<string, object> dict)
        {
            // VLESS 可以暂时用 Hysteria2Node 或 TrojanNode 的结构来存储
            // 或者创建新的 VlessNode 类，这里先返回 null
            Console.WriteLine($"[-] 暂不支持 VLESS 协议转换");
            return null;
        }
    }
}
