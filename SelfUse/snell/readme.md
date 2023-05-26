
snell v3.0.1

指导教程参考
https://iyideng.net/black-technology/cgfw/snell-server-building-and-using-tutorial.html

安装脚本：
Debian & Ubuntu 用户依次执行命令：
wget --no-check-certificate -O snell.sh https://raw.githubusercontent.com/JakATom/DE_SSSProfile/master/SelfUse/snell/snell.sh && chmod +x snell.sh && ./snell.sh



修改Snell服务器运行端口

Snell首次安装完成的默认端口号为：13254，如需修改，请在以上所有脚本运行结束后运行如下命令：

vim /etc/snell/snell-server.conf #编辑 Snell 配置文件
systemctl restart snell #重启 Snell 服务器

管理Snell服务命令：

systemctl status snell #查看运行状态
systemctl restart snell #重启Snell服务
systemctl start snell #启动Snell服务
systemctl stop snell #停止Snell服务
cat /etc/snell/snell-server.conf #查看Snell配置文件
vi /etc/snell/snell-server.conf #修改Snell配置文件
卸载Snell服务命令：

wget --no-check-certificate -O uninstall-snell.sh https://raw.githubusercontent.com/primovist/snell.sh/master/uninstall-snell.sh
chmod +x uninstall-snell.sh
./uninstall-snell.sh


server app下载地址
https://github.com/icpz/open-snell/releases

脚本和服务器软件都上载在本文件夹下
