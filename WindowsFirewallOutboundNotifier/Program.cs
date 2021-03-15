using Microsoft.Toolkit.Uwp.Notifications;
using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace WindowsFirewallOutboundNotifier
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);
        public static Dictionary<string, string> diskMap = null;

        public static Type tNetFwPolicy2 = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
        public static INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(tNetFwPolicy2);

        //bool varible for preventing duplicate notification
        public static bool displayNotification = true;

        private static List<INetFwRule> filteredRules = null;
        static void Main(string[] args)
        {
            ReadAllFirewallRules();

            while (true)
            {
                OnEntryWritten();
                GC.Collect();
                Thread.Sleep(3000);
            }
        }

        private static void OnEntryWritten()
        {
            List<EventRecord> filteredEntries = new List<EventRecord>();
            string eventFilterQuery = "*[System[(EventID=5152 or EventID=5157) and TimeCreated[timediff(@SystemTime) <= 6000]]]";
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
                if (preRuleNameComponent.Length >= 2)
                {
                    var ruleNameComponent = preRuleNameComponent[preRuleNameComponent.Length - 1];

                    var existRule = filteredRules.Any(x => x.Name.EndsWith(ruleNameComponent + " 出站连接"));
                    if (existRule == false)
                    {
                        if (displayNotification)
                        {
                            new ToastContentBuilder()
                                            .AddText("发现新的出站连接请求")
                                            .AddText(filePath)
                                            .AddText("请求建立出站连接")
                                            .AddButton(new ToastButton().SetContent("允许").AddArgument("action", "AllowConnection"))
                                            .AddButton(new ToastButton().SetContent("阻止").AddArgument("action", "BlockConnection"))
                                            .Show();
                            displayNotification = false;
                            ToastNotificationManagerCompat.OnActivated += toastArgs =>
                            {
                                ToastArguments args = ToastArguments.Parse(toastArgs.Argument);

                                FirewallActions(args, filePath, ruleNameComponent);
                                args = null;
                            };
                        }
                    }
                }

            }         
        }

        private static void ReadAllFirewallRules()
        {
            if (filteredRules != null)
            {
                filteredRules.Clear();
            }

            filteredRules = fwPolicy2.Rules.Cast<INetFwRule>().Where(x => x.Direction == NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT && x.Name.EndsWith("出站连接")).ToList();
        }

        private static void FirewallActions(ToastArguments args, string fileName, string ruleNameComponent)
        {
            var buttonSelection = args.First().Value;
            INetFwRule2 firewallRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            INetFwPolicy2 operatePolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            var existRule = filteredRules.Any(x => x.Name.EndsWith(ruleNameComponent + " 出站连接"));
            if (existRule == false)
            {
                if (buttonSelection == "AllowConnection")
                {
                    var currentProfiles = fwPolicy2.CurrentProfileTypes;
                    firewallRule.Enabled = true;
                    firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                    firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
                    firewallRule.ApplicationName = fileName;
                    firewallRule.Name = "允许 " + ruleNameComponent + " 出站连接";
                    firewallRule.Profiles = currentProfiles;
                    operatePolicy.Rules.Add(firewallRule);
                }
                else
                {
                    var currentProfiles = fwPolicy2.CurrentProfileTypes;
                    firewallRule.Enabled = true;
                    firewallRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                    firewallRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                    firewallRule.ApplicationName = fileName;
                    firewallRule.Name = "阻止 " + ruleNameComponent + " 出站连接";
                    firewallRule.Profiles = currentProfiles;
                    operatePolicy.Rules.Add(firewallRule);
                }
            }
            ReadAllFirewallRules();
            displayNotification = true;
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
                    diskMap.Add(sb.ToString().ToLower() + "\\", trimmedDrive);
                }
            }
            catch (Exception)
            {              
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
