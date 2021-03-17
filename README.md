# Windows Firewall Outbound Notifier
Windows Firewall Outbound Notifier 是一款用于提示通过Windows防火墙进行出站连接请求的轻量化的C#程序，使用.Net Core架构。该应用的提醒使用了UWP的外观，与Windows10的设计语言相切合。

# 注意：
1. 该程序没有用户界面，你需要通过Winodws防火墙本身进行详细的规则管理。
2. 请在使用前确保机器上已安装.Net Framework
3. 请确保使用者具备管理员权限

# 使用说明：
1. 在组策略中 确保"Audit filtering platform connection"和"Audit filtering platform packet drop"处于“已启用”的状态。
2. 下载并解压缩"Windows Firewall Outbound Notifier.zip"，并将其拷贝到任意目录。
3. 在解压缩的文件夹中，找到"Auto Start"文件夹，使用推荐方法或其他方法中的任一项。
4. 按文件夹内的教程或说明文件设置好开机启动。
5. 设置Windows防火墙，并将激活的配置文件设置为"阻止与规则不匹配的出站连接"。
6. 重启计算机并开始使用

# 相关参考资料:
1. https://github.com/wokhansoft/WFN - HardVolumn地址转换文件地址
2. https://github.com/windows-toolkit/WindowsCommunityToolkit - 显示UWP式的通知
3. https://stackoverflow.com/questions/2586612/how-to-keep-a-net-console-app-running - 使应用保持后台运行
4. https://stackoverflow.com/questions/2763669/how-to-hide-a-console-application-in-c-sharp -  使应用不显示用户界面
5. https://zhuanlan.zhihu.com/p/113767050 - 使应用在启动时不触发UAC提示
6. 应用图标来源: <div>Icons made by <a href="https://www.freepik.com" title="Freepik">Freepik</a> from <a href="https://www.flaticon.com/" title="Flaticon">www.flaticon.com</a></div>
