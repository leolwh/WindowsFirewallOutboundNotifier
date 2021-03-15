using Microsoft.Toolkit.Uwp.Notifications;
using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using WindowsFirewallHelper;

namespace WindowsFirewallOutboundNotifier
{
    class Magician
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int HIDE = 0;

        public static void DisappearConsole()
        {
            ShowWindow(GetConsoleWindow(), HIDE);
        }
    }
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);
        public static Dictionary<string, string> diskMap = null;

        private static List<INetFwRule> filteredRules = new List<INetFwRule>();
        static void Main(string[] args)
        {
            Magician.DisappearConsole();
 
            ReadAllFirewallRules();

            EventLog securityLogs = new EventLog("Security");
            securityLogs.EntryWritten += new EntryWrittenEventHandler(OnEntryWritten);
            securityLogs.EnableRaisingEvents = true;

            Console.ReadLine();
        }

        private static void ReadAllFirewallRules()
        {
            filteredRules.Clear();
            Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);
            List<INetFwRule> allRules = new List<INetFwRule>();
            foreach (INetFwRule ruleItem in fwPolicy2.Rules)
            {
                allRules.Add(ruleItem);
            }
            filteredRules = allRules.Where(x => x.Direction == NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT).ToList();
            fwPolicy2 = null;
            tNetFwPolicy2 = null;
        }

        private static void OnEntryWritten(object source, EntryWrittenEventArgs e)
        {
            List<EventRecord> filteredEntries = new List<EventRecord>();
            string eventFilterQuery = "*[System/EventID=5152 or System/EventID=5157]";
            EventLogQuery eventsQuery = new EventLogQuery("Security", PathType.LogName, eventFilterQuery);
            try
            {
                EventLogReader logReader = new EventLogReader(eventsQuery);
                for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
                {
                    filteredEntries.Add(eventdetail);
                }
             
            }
            catch (EventLogNotFoundException)
            {
            }
            var query = filteredEntries.OrderByDescending(x => x.TimeCreated).FirstOrDefault();
            if (query != null && query.Properties[2].Value.ToString() == @"%%14593")
            {
                var filePath = GetFriendlyPath(query.Properties[1].Value.ToString());
                var preRuleNameComponent = filePath.Split('\\');
                if (preRuleNameComponent.Length < 2)
                {
                    return;
                }
                var ruleNameComponent = preRuleNameComponent[preRuleNameComponent.Length - 1];

                var existRule = filteredRules.Any(x => x.Name == "允许 " + ruleNameComponent + " 出站连接" || x.Name == "阻止 " + ruleNameComponent + " 出站连接");
                if (existRule == false)
                {
                    new ToastContentBuilder()
                                        .AddText("发现新的出站连接请求")
                                        .AddText(filePath)
                                        .AddText("请求建立出站连接")
                                        .AddButton(new ToastButton().SetContent("允许").AddArgument("action", "AllowConnection"))
                                        .AddButton(new ToastButton().SetContent("阻止").AddArgument("action", "BlockConnection"))
                                        .Show();

                    ToastNotificationManagerCompat.OnActivated += toastArgs =>
                    {
                        ToastArguments args = ToastArguments.Parse(toastArgs.Argument);

                        FirewallActions(args, filePath, ruleNameComponent);
                        args = null;
                    };
                }

            }
            //sleep 1 second to optism performance
            Thread.Sleep(1000);
        }

        private static void FirewallActions(ToastArguments args, string fileName, string ruleNameComponent)
        {
            var buttonSelection = args.First().Value;
            if (buttonSelection == "AllowConnection")
            {
                var existRule = filteredRules.Any(x => x.Name == "允许 " + ruleNameComponent + " 出站连接");
                if (existRule == false)
                {
                    var allowedRule = FirewallManager.Instance.CreateApplicationRule(
                                       FirewallManager.Instance.GetProfile().Type, @"允许 " + ruleNameComponent + " 出站连接",
                                       FirewallAction.Allow, fileName);
                    allowedRule.Direction = FirewallDirection.Outbound;
                    allowedRule.Protocol = FirewallProtocol.Any;
                    FirewallManager.Instance.Rules.Add(allowedRule);
                }

            }
            else
            {
                var existRule = filteredRules.Any(x => x.Name == "阻止 " + ruleNameComponent + " 出站连接");
                if (existRule == false)
                {
                    var blockedRule = FirewallManager.Instance.CreateApplicationRule(
                                       FirewallManager.Instance.GetProfile().Type, @"阻止 " + ruleNameComponent + " 出站连接",
                                       FirewallAction.Block, fileName);
                    blockedRule.Direction = FirewallDirection.Outbound;
                    blockedRule.Protocol = FirewallProtocol.Any;
                    FirewallManager.Instance.Rules.Add(blockedRule);
                }
            }
            ReadAllFirewallRules();
            ToastNotificationManagerCompat.History.Clear();
        }

        private static void initDriveMapping()
        {
            try
            {
                string[] drives = Directory.GetLogicalDrives();
                diskMap = new Dictionary<string, string>(drives.Length);
                StringBuilder sb = new StringBuilder(261);
                string trimmedDrive;
                foreach (string drive in drives)
                {
                    trimmedDrive = drive.TrimEnd('\\');
                    if (QueryDosDevice(trimmedDrive, sb, (uint)sb.Capacity) == 0)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Call to QueryDosDevice failed!");
                    }
                    diskMap.Add(sb.ToString().ToLower() + "\\", trimmedDrive); //FIXME: Switch to ToUpper?
                }
            }
            catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e.StackTrace);
            }
        }

        public static string GetFriendlyPath(string p)
        {
            if (String.IsNullOrEmpty(p))
            {
                return String.Empty;
            }
            if (diskMap == null)
            {
                initDriveMapping();
            }

            KeyValuePair<string, string> item = diskMap.FirstOrDefault(d => p.StartsWith(d.Key, StringComparison.InvariantCultureIgnoreCase));
            return (item.Key == null ? System.Environment.ExpandEnvironmentVariables(p) : item.Value + p.Substring(item.Key.Length - 1));
        }
    }
}
