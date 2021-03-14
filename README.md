# WindowsFirewallOutboundNotifier
WindowsFirewallOutboundNotifier is a lightweight C# app created in .net core that will populate notification if some app reqire outbound connection via windows firewall. The Notification through this app is the modern UWP style notification, which align with windows 10 system. 
This app doesn't include the GUI interface, so you need to use the Windows Firewall itself to add/remove/change rule.

NOTE: Please make sure the .net framework is installed on the machine, otherwise, the app will not work

How to use:
1. check group policy to ensure "Audit filtering platform connection" and "Audit filtering platform packet drop" is enabled.
2. unzip "Windows Firewall Outbound Notifier.zip" file and copy it into anywhere you like.
3. in the unziipped folder, go into "Auto Start Script" , edit "start.vbs", make sure you use the correct file location.
4. Copy "start.vbs" into the startup folder to make the app start on boot.
5. Go into windows firewall and change the current activate domain profile outbound connection rule to block.
6. Enjoy.






Reference in making this app:
1. https://github.com/wokhansoft/WFN - the logic for connverting volumn address to file address
2. https://github.com/falahati/WindowsFirewallHelper - the logic for adding rules
3. https://github.com/windows-toolkit/WindowsCommunityToolkit - logic for displaying notification
4. https://stackoverflow.com/questions/2586612/how-to-keep-a-net-console-app-running - logic for keeping app run in background
5. https://stackoverflow.com/questions/2763669/how-to-hide-a-console-application-in-c-sharp -  logic for keeping app run in background
6. icon: <div>Icons made by <a href="https://www.freepik.com" title="Freepik">Freepik</a> from <a href="https://www.flaticon.com/" title="Flaticon">www.flaticon.com</a></div>
