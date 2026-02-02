using System.Text.RegularExpressions;
using System.Web;

namespace Befree
{
    public class Hysteria2Node : Node
    {
        public string Name { get; set; }
        public string Server { get; set; }
        public int Port { get; set; }
        public string Password { get; set; }
        public string Sni { get; set; }
        public bool SkipCertVerify { get; set; }

        public static Hysteria2Node Parse(string url)
        {
            try
            {
                string password = string.Empty;
                string server = string.Empty;
                int port = 443; // 默认端口
                string sni = string.Empty;
                bool skipCertVerify = false;
                string name = string.Empty;

                // 解析名称 (#后面的部分)
                if (url.Contains('#'))
                {
                    string[] parts = url.Split('#');
                    name = HttpUtility.UrlDecode(parts[1]).Trim();
                    url = parts[0];
                }
                if (string.IsNullOrEmpty(name)) { name = "xxxx"; }

                // 解析参数 (?后面的部分)
                if (url.Contains('?'))
                {
                    string[] parts = url.Split('?');
                    string queryParams = parts[1];
                    url = parts[0];

                    // 解析查询参数
                    var paramsDict = ParseQueryString(queryParams);
                    if (paramsDict.ContainsKey("sni"))
                    {
                        sni = paramsDict["sni"];
                    }
                    if (paramsDict.ContainsKey("insecure"))
                    {
                        skipCertVerify = paramsDict["insecure"] == "1" || paramsDict["insecure"].ToLower() == "true";
                    }
                }

                // 移除协议前缀
                if (url.StartsWith("hysteria2://"))
                {
                    url = url.Substring(12);
                }
                else if (url.StartsWith("hy2://"))
                {
                    url = url.Substring(6);
                }

                // 解析密码和服务器信息
                if (url.Contains('@'))
                {
                    string[] parts = url.Split('@');
                    password = parts[0];

                    // 解析服务器和端口
                    string serverPort = parts[1];
                    if (serverPort.Contains(':'))
                    {
                        string[] serverPortParts = serverPort.Split(':');
                        server = serverPortParts[0].Trim();
                        if (serverPortParts.Length > 1)
                        {
                            port = int.Parse(serverPortParts[1].Trim());
                        }
                    }
                    else
                    {
                        server = serverPort.Trim();
                    }
                }
                else
                {
                    // 没有密码的情况
                    if (url.Contains(':'))
                    {
                        string[] serverPortParts = url.Split(':');
                        server = serverPortParts[0].Trim();
                        if (serverPortParts.Length > 1)
                        {
                            port = int.Parse(serverPortParts[1].Trim());
                        }
                    }
                    else
                    {
                        server = url.Trim();
                    }
                }

                return new Hysteria2Node
                {
                    Name = name,
                    Server = server,
                    Port = port,
                    Password = password,
                    Sni = sni,
                    SkipCertVerify = skipCertVerify
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] 发现一处Hysteria2节点 {HttpUtility.UrlDecode(url)} 转换错误，非正常命名节点。");
                return null;
            }
        }

        private static Dictionary<string, string> ParseQueryString(string queryString)
        {
            var dict = new Dictionary<string, string>();
            string[] pairs = queryString.Split('&');
            foreach (string pair in pairs)
            {
                string[] kv = pair.Split('=');
                if (kv.Length == 2)
                {
                    dict[HttpUtility.UrlDecode(kv[0])] = HttpUtility.UrlDecode(kv[1]);
                }
            }
            return dict;
        }

        public override object ToClashProxy()
        {
            var proxyDict = new Dictionary<string, object>
            {
                { "name", Name },
                { "type", "hysteria2" },
                { "server", Server },
                { "port", Port }
            };

            if (!string.IsNullOrEmpty(Password))
            {
                proxyDict["password"] = Password;
            }

            if (!string.IsNullOrEmpty(Sni))
            {
                proxyDict["sni"] = Sni;
            }

            proxyDict["skip-cert-verify"] = SkipCertVerify;

            return proxyDict;
        }
    }
}
