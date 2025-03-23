import ctypes
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import re

def is_admin():
    """检查是否具有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # 请求管理员权限
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, None, 1)
    sys.exit()

class IPConfigApp:
    def __init__(self, master):
        self.master = master
        master.title("静态IP配置工具")
        master.resizable(False, False)

        # 获取网络接口信息
        self.interfaces = self.get_interfaces_info()
        if not self.interfaces:
            messagebox.showerror("错误", "无法获取网络接口信息")
            sys.exit()
            
        # 创建用户输入缓存字典
        self.user_inputs = {}
        for if_name in self.interfaces:
            self.user_inputs[if_name] = {
                "ip": self.interfaces[if_name]["ip"],
                "subnet": self.interfaces[if_name]["subnet"],
                "gateway": self.interfaces[if_name]["gateway"],
                "dns1": self.interfaces[if_name]["dns"][0] if self.interfaces[if_name]["dns"] else "",
                "dns2": self.interfaces[if_name]["dns"][1] if len(self.interfaces[if_name]["dns"]) > 1 else ""
            }
        # 记录当前选择的接口
        self.current_interface = None

        # 界面布局
        self.create_widgets()
        
        # 默认选择第一个接口
        if self.interfaces:
            self.interface_combo.current(0)
            self.current_interface = self.interface_combo.get()
            self.update_interface_entries()

    def create_widgets(self):
        """创建界面组件"""
        style = ttk.Style()
        style.configure("TLabel", padding=5)
        style.configure("TButton", padding=5)
        # 网络接口选择
        ttk.Label(self.master, text="网络接口:").grid(row=0, column=0, sticky="e")
        self.interface_combo = ttk.Combobox(self.master, values=list(self.interfaces.keys()), width=30)
        self.interface_combo.grid(row=0, column=1, columnspan=2, padx=5, pady=5)
        self.interface_combo.bind("<<ComboboxSelected>>", self.on_interface_changed)

        # IP配置输入
        ttk.Label(self.master, text="IP地址:").grid(row=1, column=0, sticky="e")
        self.ip_entry = ttk.Entry(self.master)
        self.ip_entry.grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(self.master, text="子网掩码:").grid(row=2, column=0, sticky="e")
        self.subnet_entry = ttk.Entry(self.master)
        self.subnet_entry.grid(row=2, column=1, padx=5, pady=2)

        ttk.Label(self.master, text="默认网关:").grid(row=3, column=0, sticky="e")
        self.gateway_entry = ttk.Entry(self.master)
        self.gateway_entry.grid(row=3, column=1, padx=5, pady=2)

        # DNS配置
        ttk.Label(self.master, text="首选DNS:").grid(row=4, column=0, sticky="e")
        self.dns1_entry = ttk.Entry(self.master)
        self.dns1_entry.grid(row=4, column=1, padx=5, pady=2)

        ttk.Label(self.master, text="备用DNS:").grid(row=5, column=0, sticky="e")
        self.dns2_entry = ttk.Entry(self.master)
        self.dns2_entry.grid(row=5, column=1, padx=5, pady=2)

        # 操作按钮
        ttk.Button(self.master, text="刷新网络信息", command=self.refresh_network_info).grid(row=4, column=2, padx=5)
        self.apply_button = ttk.Button(self.master, text="应用配置", command=self.apply_settings)
        self.apply_button.grid(row=6, column=1, pady=10)

    def save_current_inputs(self):
        """保存当前接口的输入到缓存"""
        if not self.current_interface or self.current_interface not in self.interfaces:
            return
            
        # 修改点：无论接口是否启用都保存用户输入
        self.user_inputs[self.current_interface] = {
            "ip": self.ip_entry.get().strip(),
            "subnet": self.subnet_entry.get().strip(),
            "gateway": self.gateway_entry.get().strip(),
            "dns1": self.dns1_entry.get().strip(),
            "dns2": self.dns2_entry.get().strip()
        }

    def on_interface_changed(self, event):
        """接口切换事件处理"""
        # 保存当前接口的输入
        old_interface = self.current_interface
        self.save_current_inputs()
        
        # 更新当前接口
        self.current_interface = self.interface_combo.get()
        
        # 更新界面
        self.update_interface_entries()

    def get_interfaces_info(self):
        """获取网络接口信息"""
        try:
            output = subprocess.check_output(['ipconfig', '/all'], encoding='cp936')
        except subprocess.CalledProcessError:
            return {}

        interfaces = {}
        current_if = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # 匹配网络接口名称
            if_match = re.match(r'^(.+适配器)\s(.+):$', line)
            if if_match:
                current_if = if_match.group(2)
                interfaces[current_if] = {
                    "dns": [],
                    "ip": "",
                    "subnet": "",
                    "gateway": "",
                    "enabled": False
                }
                continue
            
            # 只处理当前接口的信息
            if current_if:
                # 匹配IP地址
                if "IPv4 地址" in line or "IP 地址" in line:
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if ip_match:
                        interfaces[current_if]["ip"] = ip_match.group(0)
                        interfaces[current_if]["enabled"] = True
                
                # 匹配子网掩码
                elif "子网掩码" in line:
                    subnet_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if subnet_match:
                        interfaces[current_if]["subnet"] = subnet_match.group(0)
                
                # 匹配默认网关
                elif "默认网关" in line:
                    gateway_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if gateway_match:
                        interfaces[current_if]["gateway"] = gateway_match.group(0)
                
                # 匹配DNS信息
                elif "DNS 服务器" in line:
                    dns_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if dns_match:
                        interfaces[current_if]["dns"].append(dns_match.group(0))
        
        return interfaces

    def update_interface_entries(self):
        """更新所有界面输入值"""
        if_name = self.current_interface
        if not if_name or if_name not in self.interfaces:
            return
        
        # 控制应用按钮的显示状态
        if self.interfaces[if_name]["enabled"]:
            self.apply_button.grid()  # 显示按钮
        else:
            self.apply_button.grid_remove()  # 隐藏按钮

        interface_data = self.interfaces[if_name]

        # 清空所有输入框
        self.ip_entry.delete(0, tk.END)
        self.subnet_entry.delete(0, tk.END)
        self.gateway_entry.delete(0, tk.END)
        self.dns1_entry.delete(0, tk.END)
        self.dns2_entry.delete(0, tk.END)

        # 首先检查是否存在用户缓存的数据
        if if_name in self.user_inputs:
            user_data = self.user_inputs[if_name]
            self.ip_entry.insert(0, user_data["ip"])
            self.subnet_entry.insert(0, user_data["subnet"])
            self.gateway_entry.insert(0, user_data["gateway"])
            self.dns1_entry.insert(0, user_data["dns1"])
            self.dns2_entry.insert(0, user_data["dns2"])
        else:
            # 如果没有缓存数据，使用接口信息
            if interface_data["ip"]:
                self.ip_entry.insert(0, interface_data["ip"])
            if interface_data["subnet"]:
                self.subnet_entry.insert(0, interface_data["subnet"])
            if interface_data["gateway"]:
                self.gateway_entry.insert(0, interface_data["gateway"])
            
            dns_servers = interface_data["dns"]
            if len(dns_servers) > 0:
                self.dns1_entry.insert(0, dns_servers[0])
            if len(dns_servers) > 1:
                self.dns2_entry.insert(0, dns_servers[1])

    def refresh_network_info(self):
        """刷新网络信息"""
        # 保存当前接口的输入
        self.save_current_inputs()
        
        # 记录旧的用户输入
        old_inputs = self.user_inputs.copy()
        
        # 记录当前选择的接口
        current_if = self.current_interface
        
        # 刷新网络信息
        self.interfaces = self.get_interfaces_info()
        if not self.interfaces:
            messagebox.showerror("错误", "无法获取网络接口信息")
            return
        
        # 更新下拉框选项
        self.interface_combo['values'] = list(self.interfaces.keys())
        
        # 合并旧的用户输入到新接口数据
        self.user_inputs = {}
        for if_name in self.interfaces:
            # 保留旧接口的配置
            if if_name in old_inputs:
                self.user_inputs[if_name] = old_inputs[if_name]
            else:
                # 新接口使用默认配置
                self.user_inputs[if_name] = {
                    "ip": self.interfaces[if_name]["ip"],
                    "subnet": self.interfaces[if_name]["subnet"],
                    "gateway": self.interfaces[if_name]["gateway"],
                    "dns1": self.interfaces[if_name]["dns"][0] if self.interfaces[if_name]["dns"] else "",
                    "dns2": self.interfaces[if_name]["dns"][1] if len(self.interfaces[if_name]["dns"]) > 1 else ""
                }
        
        # 如果当前选择的接口仍然存在，保持选择
        if current_if and current_if in self.interfaces:
            self.interface_combo.set(current_if)
        else:
            # 否则选择第一个接口
            if self.interfaces:
                self.interface_combo.current(0)
                current_if = self.interface_combo.get()
            else:
                current_if = None
        
        # 更新当前接口变量
        self.current_interface = current_if
        
        # 更新界面显示
        if current_if:
            self.update_interface_entries()
        
        messagebox.showinfo("成功", "网络信息已刷新")

    def validate_ip(self, ip):
        """验证IP地址格式"""
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(pattern, ip) is not None

    def apply_settings(self):
        """应用网络配置"""
        if_name = self.current_interface
        if not if_name or if_name not in self.interfaces:
            return
        
        # 检查接口是否有效
        if not self.interfaces[if_name]["enabled"]:
            messagebox.showerror("错误", f"接口 '{if_name}' 未获取到IP地址，不可配置")
            return
        
        # 保存当前输入到缓存
        self.save_current_inputs()
        
        # 从缓存读取数据
        cached_data = self.user_inputs.get(if_name, {})
        ip = cached_data.get("ip", "").strip()
        subnet = cached_data.get("subnet", "").strip()
        gateway = cached_data.get("gateway", "").strip()
        dns1 = cached_data.get("dns1", "").strip()
        dns2 = cached_data.get("dns2", "").strip()

        # 输入验证
        if not ip or not subnet or not gateway:
            messagebox.showerror("错误", "IP地址、子网掩码和网关不能为空")
            return
            
        if not all([self.validate_ip(f) for f in [ip, subnet, gateway] if f]):
            messagebox.showerror("错误", "请输入有效的IP地址、子网掩码和网关格式")
            return
            
        if dns1 and not self.validate_ip(dns1):
            messagebox.showerror("错误", "请输入有效的首选DNS格式")
            return
            
        if dns2 and not self.validate_ip(dns2):
            messagebox.showerror("错误", "请输入有效的备用DNS格式")
            return

        try:
            # 设置静态IP命令
            ip_cmd = f'netsh interface ip set address name="{if_name}" static {ip} {subnet} {gateway} 1'
            
            # 显示执行的命令（调试用）
            print(f"执行命令: {ip_cmd}")
            
            # 执行IP设置命令并捕获输出
            process = subprocess.Popen(
                ip_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True
            )
            stdout, stderr = process.communicate()
            
            # 检查命令执行结果
            if process.returncode != 0:
                error_msg = f"设置IP地址失败，错误代码: {process.returncode}\n输出: {stdout}\n错误: {stderr}"
                print(error_msg)  # 控制台输出
                messagebox.showerror("错误", error_msg)
                return
                
            # 设置DNS (如果提供了DNS)
            if dns1:
                dns_cmd = f'netsh interface ip set dns name="{if_name}" static {dns1}'
                print(f"执行命令: {dns_cmd}")
                
                process = subprocess.Popen(
                    dns_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True,
                    text=True
                )
                stdout, stderr = process.communicate()
                
                if process.returncode != 0:
                    error_msg = f"设置DNS失败，错误代码: {process.returncode}\n输出: {stdout}\n错误: {stderr}"
                    print(error_msg)
                    messagebox.showerror("错误", error_msg)
                    return
            
            # 设置备用DNS (如果提供了备用DNS)
            if dns2:
                dns2_cmd = f'netsh interface ip add dns name="{if_name}" {dns2} index=2'
                print(f"执行命令: {dns2_cmd}")
                
                process = subprocess.Popen(
                    dns2_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True,
                    text=True
                )
                stdout, stderr = process.communicate()
                
                if process.returncode != 0:
                    error_msg = f"设置备用DNS失败，错误代码: {process.returncode}\n输出: {stdout}\n错误: {stderr}"
                    print(error_msg)
                    messagebox.showwarning("警告", error_msg)  # 使用警告而不是错误，因为主要功能已完成
            
            # 刷新界面数据
            self.refresh_network_info()
            messagebox.showinfo("成功", "网络配置已成功应用")
            
        except Exception as e:
            error_msg = f"配置失败: {str(e)}"
            print(error_msg)
            messagebox.showerror("错误", error_msg)

if __name__ == "__main__":
    root = tk.Tk()
    app = IPConfigApp(root)
    root.mainloop()