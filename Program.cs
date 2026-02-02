using System.Text.RegularExpressions;
using System.Text;
using Befree;
class Program
{

    static void Main(string[] args)
    {
        string inputFile = "./aaa.txt";
        string localYamlFiles = "";
        int listenPort = 59981;
        string SpeedUrl = "https://www.google.com";
        var Yamlfile = "sectest.yaml";
        var parsedArgs = ArgsParser.ParseArgs(args);
        if (parsedArgs.Count == 0){return;}
        if (parsedArgs.ContainsKey("-f")){inputFile = parsedArgs["-f"];}
        if (parsedArgs.ContainsKey("-l")){localYamlFiles = parsedArgs["-l"];}  // 本地 YAML 文件列表
        if (parsedArgs.ContainsKey("-p")){if (int.TryParse(parsedArgs["-p"], out int parsedPort)){listenPort = parsedPort;}else{Console.WriteLine("[-] 无效的端口号。使用默认端口 1081。");}}
        if (parsedArgs.ContainsKey("-t")){SpeedUrl = parsedArgs["-t"];}
        if (parsedArgs.ContainsKey("-y"))
        {
            Yamlfile = parsedArgs["-y"];
            if (File.Exists(Yamlfile))
            {
                Console.WriteLine($" [+] 检测到 {Yamlfile} 文件，程序正在启动");
                ClashRunner.RunClash(Yamlfile);
            }
        }else{RunMain(inputFile, localYamlFiles, listenPort, SpeedUrl);};
    }

    static void RunMain(string inputFile, string localYamlFiles, int listenPort, string SpeedUrl)
    {
        Console.WriteLine("Befree v0.5 ————迷人安全");
        string outputFile = "sectest.yaml";

        // 全局计数器,统计各类型节点总共获取数量
        int totalVmessCount = 0;
        int totalSsCount = 0;
        int totalSsrCount = 0;
        int totalTrojanCount = 0;
        int totalHysteria2Count = 0;

        var allNodes = new List<Node>();

        //1. 检查输入文件类型并加载
        if (inputFile.EndsWith(".yaml") || inputFile.EndsWith(".yml"))
        {
            // 本地 YAML 配置文件
            Console.WriteLine($" [+] 检测到 YAML 配置文件，正在解析本地节点");
            var nodes = YamlConfigParser.ParseYamlFile(inputFile, ref totalVmessCount, ref totalSsCount, ref totalTrojanCount, ref totalHysteria2Count);
            allNodes.AddRange(nodes);
        }
        else
        {
            // 订阅地址文件
            var subscriptionUrls = LoadSubscriptionUrls(inputFile);
            Console.WriteLine($" [+] {inputFile}文件中，发现{subscriptionUrls.Count} 个订阅地址");

            //2.请求订阅并解析
            foreach(var url in subscriptionUrls)
            {
                //Console.WriteLine($" [+] 正在处理订阅地址：{url}");
                var nodes = FetchAndParseSubscription(url, ref totalVmessCount, ref totalSsCount, ref totalSsrCount, ref totalTrojanCount, ref totalHysteria2Count);
                allNodes.AddRange(nodes);
            }
        }

        //3. 如果指定了本地 YAML 文件，解析并添加
        if (!string.IsNullOrEmpty(localYamlFiles))
        {
            string[] files = localYamlFiles.Split(',', '|');
            foreach (var file in files)
            {
                string trimmedFile = file.Trim();
                if (File.Exists(trimmedFile))
                {
                    Console.WriteLine($" [+] 正在解析本地 YAML 文件：{trimmedFile}");
                    var nodes = YamlConfigParser.ParseYamlFile(trimmedFile, ref totalVmessCount, ref totalSsCount, ref totalTrojanCount, ref totalHysteria2Count);
                    allNodes.AddRange(nodes);
                }
                else
                {
                    Console.WriteLine($" [-] 文件不存在：{trimmedFile}");
                }
            }
        }

        Console.WriteLine($" [+] 总共解析到{allNodes.Count} 个正常转换节点");
        // 输出所有协议类型节点的总数
        Console.WriteLine($" [+] 其中包含vmess节点数量为: {totalVmessCount}");
        Console.WriteLine($" [+] 其中包含ss节点数量为: {totalSsCount}");
        //Console.WriteLine($" [+] 其中包含ssr节点数量为: {totalSsrCount}**");
        Console.WriteLine($" [+] 其中包含trojan节点数量为: {totalTrojanCount}");
        Console.WriteLine($" [+] 其中包含hysteria2节点数量为: {totalHysteria2Count}");

        //3.生成clash配置文件
        if (allNodes.Count > 0){
            ClashConfigManager.GenerateConfig(allNodes,outputFile,listenPort,SpeedUrl);
            //4.运行clash
            ClashRunner.RunClash(outputFile);
        }else{Console.WriteLine($" [-] 未获取到可用节点，无法启动befree");}

    }

    //统计订阅文件中有多少订阅地址
    static List<string> LoadSubscriptionUrls(string filePath)
    {
        if(!File.Exists(filePath))
        {
            throw new FileNotFoundException($"订阅文件未找到：{filePath}");
        }
        var urls = new List<string>();
        foreach (var line in File.ReadAllLines(filePath))
        {
            string trimmedLine = line.Trim();
            // 过滤掉空行和不是 http/https 开头的行
            if (!string.IsNullOrEmpty(trimmedLine) &&
                (trimmedLine.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                 trimmedLine.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
            {
                urls.Add(trimmedLine);
            }
        }
        return urls;
    }
    static List<Node> ParseNodes(string rawData, ref int totalVmessCount, ref int totalSsCount, ref int totalSsrCount, ref int totalTrojanCount, ref int totalHysteria2Count)
    {
        var nodes = new List<Node>();
        foreach (var line in rawData.Split('\n'))
        {
            Node node = null;
            if (line.StartsWith("vmess://"))
            {
                node = VmessNode.FromBase64(line.Substring(8));
                totalVmessCount++;
            }
            else if(line.StartsWith("ss://"))
            {
                node = ShadowsocksNode.Parse(line.Substring(5));
                totalSsCount++;
            }
            else if (line.StartsWith("ssr://"))
            {
                totalSsrCount++;
            }
            else if (line.StartsWith("trojan://"))
            {
                node = TrojanNode.Parse(line.Substring(9));
                totalTrojanCount++;
            }
            else if (line.StartsWith("hysteria2://") || line.StartsWith("hy2://"))
            {
                string protocolPrefix = line.StartsWith("hysteria2://") ? "hysteria2://" : "hy2://";
                node = Hysteria2Node.Parse(line.Substring(protocolPrefix.Length));
                totalHysteria2Count++;
            }
            if (node != null){nodes.Add(node);}
        }
        return nodes;
    }

    //请求解析订阅
    static List<Node> FetchAndParseSubscription(string url, ref int totalVmessCount, ref int totalSsCount, ref int totalSsrCount, ref int totalTrojanCount, ref int totalHysteria2Count)
    {
        try
        {
            using var client = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(10)
            };
            var response = client.GetStringAsync(url).Result;
            Console.WriteLine($" [+] 订阅获取成功： {url}");
            if (response.Contains("proxy-groups")){
                //Console.WriteLine($" [+] 暂不支持clash订阅地址转换 {url}，请自行修改！");
                return new List<Node>();
            }
            var dec = Convert.FromBase64String(cleanBase64String(response));
            string decodedData = Encoding.UTF8.GetString(dec);
            return ParseNodes(decodedData, ref totalVmessCount, ref totalSsCount, ref totalSsrCount, ref totalTrojanCount, ref totalHysteria2Count);
        }
        catch (Exception ex)
        {
            Console.WriteLine($" [-] 处理订阅地址 {url} 时出错: {ex.Message}");
            return new List<Node>();
        }
    }
    static HttpClient CreateHttpClient()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
        };
        return new HttpClient(handler);
    }

    public static string cleanBase64String(string base64){
        string Base64String = base64.Replace("\n", "").Replace("\r", "").Trim();
        if (Base64String.Length % 4 != 0)
        {
            Base64String = Base64String.PadRight(Base64String.Length + (4 - Base64String.Length % 4), '=');
        }
        return Base64String;
    }
}