using System;
using System.Collections.Generic;
using Figgle;

namespace Befree
{
    public class ArgsParser
    {
        public static Dictionary<string, string> ParseArgs(string[] args)
        {
            string banner = FiggleFonts.Standard.Render("B e f r e e !!!");
            Console.WriteLine(banner);

            var parsedArgs = new Dictionary<string, string>();

            if (args.Length == 0)
            {
                ShowHelp();
                return parsedArgs;
            }

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-h":
                        ShowHelp();
                        Environment.Exit(0); // 退出程序，不再处理后续参数
                        break;
                    case "-f":
                        if (i + 1 < args.Length)
                        {
                            parsedArgs["-f"] = args[i + 1];
                            i++; // 跳过值
                        }
                        else
                        {
                            Console.WriteLine("Error: -f option requires a file path.");
                        }
                        break;
                    case "-p":
                        if (i + 1 < args.Length)
                        {
                            parsedArgs["-p"] = args[i + 1];
                            i++; // 跳过值
                        }
                        else
                        {
                            Console.WriteLine("Error: -p option requires a port number.");
                        }
                        break;
                    case "-t":
                        if (i + 1 < args.Length)
                        {
                            parsedArgs["-t"] = args[i + 1];
                            i++;
                        }else{Console.WriteLine("Error: -t option requires a speed url");};
                        break;
                    case "-y":
                        if (i + 1 < args.Length)
                        {
                            parsedArgs["-y"] = args[i + 1];
                            i++;
                        }else{Console.WriteLine("Error: -y option requires a yourself clash yaml file");};
                        break;
                    case "-l":
                        if (i + 1 < args.Length)
                        {
                            parsedArgs["-l"] = args[i + 1];
                            i++;
                        }else{Console.WriteLine("Error: -l option requires local yaml files (comma separated)");};
                        break;
                    default:
                        Console.WriteLine($"Unrecognized argument: {args[i]}");
                        Environment.Exit(1);
                        break;
                }
            }

            return parsedArgs;
        }

        // 显示帮助信息
        private static void ShowHelp()
        {
            Console.WriteLine("Befree v0.5 ————迷人安全");
            Console.WriteLine("by: https://github.com/yn8rt");
            Console.WriteLine("Usage:");
            Console.WriteLine("  -h      查看帮助");
            Console.WriteLine("  -f      指定一个包含订阅文件的路径");
            Console.WriteLine("  -l      指定本地YAML文件(逗号分隔，例如:file1.yaml,file2.yaml)");
            Console.WriteLine("  -p      指定端口号(http和socks5,默认59918)");
            Console.WriteLine("  -t      指定一个用于速度测试的链接(默认:https://www.google.com)");
            Console.WriteLine("  -y      指定一个自己的Clash Yaml文件");
        }
    }
}
