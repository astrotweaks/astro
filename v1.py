import tkinter as tk
from tkinter import messagebox, ttk
import random
import subprocess
import os
import urllib.request
import shutil
import requests


class Particle:
    def __init__(self, canvas, x, y):
        self.canvas = canvas
        self.id = canvas.create_oval(x, y, x+4, y+4, fill="#00ff00")  
        self.vx = random.uniform(-1, 1)
        self.vy = random.uniform(-1, 1)
    
    def move(self):
        self.canvas.move(self.id, self.vx, self.vy)
        self._check_bounds()

    def _check_bounds(self):
        x1, y1, x2, y2 = self.canvas.coords(self.id)
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        if x1 < 0 or x2 > width:
            self.vx = -self.vx
        if y1 < 0 or y2 > height:
            self.vy = -self.vy

class CurvedFrame(tk.Canvas):
    def __init__(self, master=None, corner_radius=10, **kwargs):
        self.corner_radius = corner_radius
        self._tl_id = self._tr_id = self._bl_id = self._br_id = None
        tk.Canvas.__init__(self, master, **kwargs)
        self.bind("<Configure>", self._on_configure)

    def _create_rounded_rect(self, x1, y1, x2, y2, **kwargs):
        return self.create_polygon(
            (x1+self.corner_radius, y1),
            (x1+self.corner_radius, y1),
            (x2-self.corner_radius, y1),
            (x2-self.corner_radius, y1),
            (x2, y1),
            (x2, y1),
            (x2, y1+self.corner_radius),
            (x2, y1+self.corner_radius),
            (x2, y2-self.corner_radius),
            (x2, y2-self.corner_radius),
            (x2, y2),
            (x2, y2),
            (x2-self.corner_radius, y2),
            (x2-self.corner_radius, y2),
            (x1+self.corner_radius, y2),
            (x1+self.corner_radius, y2),
            (x1, y2),
            (x1, y2),
            (x1, y2-self.corner_radius),
            (x1, y2-self.corner_radius),
            (x1, y1+self.corner_radius),
            (x1, y1+self.corner_radius),
            (x1, y1),
            (x1, y1),
            **kwargs
        )

    def _on_configure(self, event):
        self.delete("all")
        width = self.winfo_width()
        height = self.winfo_height()
        self._tl_id = self._create_rounded_rect(0, 0, self.corner_radius*2, self.corner_radius*2, fill="#000000", outline="")
        self._tr_id = self._create_rounded_rect(width, 0, width-self.corner_radius*2, self.corner_radius*2, fill="#000000", outline="")
        self._bl_id = self._create_rounded_rect(0, height, self.corner_radius*2, height-self.corner_radius*2, fill="#000000", outline="")
        self._br_id = self._create_rounded_rect(width, height, width-self.corner_radius*2, height-self.corner_radius*2, fill="#000000", outline="")

class DownloadApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ASTRO TWEAKS V1")
        self.root.geometry("1200x500")
        self.root.resizable(False, False) 
        
                
        self.style = ttk.Style()
        

        
        self.style.configure('title', background='black')
        

        self.frame = CurvedFrame(root, corner_radius=30, bg="black")
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(self.frame, width=800, height=600, bg="#000000", highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self.particles = []
        for _ in range(100):
            x = random.randint(0, 800)
            y = random.randint(0, 600)
            particle = Particle(self.canvas, x, y)
            self.particles.append(particle)
        self.animate_particles()

        self.label = ttk.Label(self.frame, text="ASTRO TWEAKS V1", background="#000000", foreground="#ffffff", font=("Akira Expanded", 40))
        self.label.place(relx=0.5, rely=0.1, anchor=tk.CENTER)
        

        self.create_buttons()

    def create_buttons(self):
        button_style = {"foreground": "#ffffff", "font": ("Akira Expanded", 20), "padding": 20, "borderwidth": 0, "background": "#008000"}  

        self.buttons_frame = tk.Frame(self.frame, bg="#000000")
        self.buttons_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        buttons_info = [
            ("Restore Point", self.create_restore_point),
            ("BIOS", self.bios_tweaks),
            ("NVIDIA", self.nvidia_tweaks),
            ("Remove Cortana", self.disable_cortana_search),
            ("Remove Game Bar", self.disable_game_bar),
            ("Activate Dark Mode", self.disable_transparency_dark_mode),
            ("INTEL", self.toggle_game_mode),
            ("Clean Windows", self.clean),
            ("Win32 Priority", self.win32),
            ("Nvidia Profile Inspector", self.install),
            ("Remove Bloatware", self.debloat),
            ("AV1 Wallpaper", self.wallpaper)
        ]

        for i, (text, command) in enumerate(buttons_info):
            button = ttk.Button(self.buttons_frame, text=text, command=command, style="Custom.TButton")
            button.grid(row=i//2, column=i%2, padx=10, pady=10, sticky="ew")

    def animate_particles(self):
        for particle in self.particles:
            particle.move()
        self.root.after(50, self.animate_particles)

    def download_file(self):
        
        subprocess.run(['curl', '-g', '-k', '-L', '-#', '-o', 'C:\\AV1.ico', 'https://cdn.discordapp.com/attachments/1182472890684276766/1241235666080239747/AV1.ico?ex=6649764b&is=664824cb&hm=a662dec9966b3b0991606895a313d7677eda0aaa9a51339f4c4ee52a9a7326df&'])

    def set_icon(self):
        icon_path = r"C:\AV1.ico"
        self.root.iconbitmap(icon_path)
        
        
    def run(self):
        
        self.download_file()
       
        
        self.set_icon()

       
        

        



    def create_restore_point(self):
         subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-Command', "Checkpoint-Computer -Description 'AV1' -RestorePointType 'MODIFY_SETTINGS'"])
         messagebox.showinfo("Info", "Punto de restauración creado exitosamente.")
    pass
    def bios_tweaks(self):
        
        commands = [
            r'Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f',
            r'Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f',
            r'Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f',
            r'Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f',
            r'Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f',
            r'Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f',
            'timeout /t 1 /nobreak > NUL',
            'bcdedit /set tscsyncpolicy legacy',
            'echo tscsyncpolicy legacy',
            'timeout /t 1 /nobreak > NUL',
            'bcdedit /set hypervisorlaunchtype off',
            'echo Disable Hyper-V',
            'timeout /t 1 /nobreak > NUL',
            'bcdedit /set linearaddress57 OptOut',
            'bcdedit /set increaseuserva 268435328',
            'echo Linear Address 57',
            'timeout /t 1 /nobreak > NUL',
            'bcdedit /set isolatedcontext No',
            'bcdedit /set allowedinmemorysettings 0x0',
            'echo Kernel memory mitigations',
            'timeout /t 1 /nobreak > NUL',
            'bcdedit /set vsmlaunchtype Off',
            'bcdedit /set vm No',
            r'Reg.exe add "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f',
            r'Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f',
            r'Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f',
            'echo DMA memory protection and cores isolation',
            'timeout /t 1 /nobreak > NUL',
            'bcdedit /set x2apicpolicy Enable',
            'bcdedit /set uselegacyapicmode No',
            'echo Enable X2Apic',
            'timeout /t 1 /nobreak > NUL',
            'bcdedit /set configaccesspolicy Default',
            'bcdedit /set MSI Default',
            'bcdedit /set usephysicaldestination No',
            'bcdedit /set usefirmwarepcisettings No'
        ]

       
        for command in commands:
            subprocess.Popen(command, shell=True)

        
        subprocess.run('powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'DONE!\')"', shell=True)
    pass
        

    def nvidia_tweaks(self):
        commands = [
            r'Reg.exe add "HKCU\SOFTWARE\NVIDIA Corporation\Global\NVTweak\Devices\509901423-0\Color" /v "NvCplUseColorCorrection" /t REG_DWORD /d "0" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t REG_DWORD /d "0" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v EnableRID73779  /t REG_DWORD /d 1 /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v EnableRID73780  /t REG_DWORD /d 1 /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v EnableRID74361  /t REG_DWORD /d 1 /f',
            r'Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID44231  /t REG_DWORD /d 0 /f',
            r'Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID64640  /t REG_DWORD /d 0 /f',
            r'Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID66610  /t REG_DWORD /d 0 /f',
            r'Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v OptInOrOutPreference /t REG_DWORD /d 0 /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" /v Start /t REG_DWORD /d 4 /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v SendTelemetryData /t REG_DWORD /d 0 /f',
            r'Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\Startup\SendTelemetryData" /v 0 /t REG_DWORD /d 0 /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PlatformSupportMiracast" /t REG_DWORD /d "0" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DesktopStereoShortcuts" /t REG_DWORD /d "0" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "FeatureControl" /t REG_DWORD /d "4" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "NVDeviceSupportKFilter" /t REG_DWORD /d "0" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmCacheLoc" /t REG_DWORD /d "0" /f'
        ]

        for command in commands:
            subprocess.Popen(command, shell=True)

        
        subprocess.run('powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'DONE!\')"', shell=True)
    
        pass

    def disable_cortana_search(self):
       
        commands = [
            'Reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f',
            'Reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f',
            'Reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f',
            'Reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f',
            'Reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f',
            'Reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f',
            'Reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "0" /f',
            'Powershell -Command "Get-appxpackage -allusers *Microsoft.549981C3F5F10* | Remove-AppxPackage"'
        ]

       
        for command in commands:
            subprocess.run(command, shell=True)

        
        subprocess.run('powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'DONE!\')"', shell=True)

    def disable_game_bar(self):
        
        commands = [
            r'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f',
            r'reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f'
        ]
        for command in commands:
            subprocess.run(command, shell=True)

        
        subprocess.run('powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'DONE!\')"', shell=True)

    def disable_transparency_dark_mode(self):
        
        commands = [
            r'reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f',
            r'reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f',
            r'reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f'
        ]

       
        for command in commands:
            subprocess.run(command, shell=True)

        #
        subprocess.run('powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'DONE!\')"', shell=True)

    def toggle_game_mode(self):
        commands = [
            'bcdedit /set allowedinmemorysettings 0x0',
            'bcdedit /set isolatedcontext No',
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel" /v "DisableTsx" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f',
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f',
            'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f'
        ]

        
        for command in commands:
            subprocess.Popen(command, shell=True)

        
        subprocess.run('powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'DONE!\')"', shell=True)

    def clean(self):
        commands = [
            'del /s /q /f c:\\windows\\temp.',
            'del /s /q /f C:\\WINDOWS\\Prefetch',
            'del /s /q /f %temp%.',
            'del /s /q /f %systemdrive%\\*.tmp',
            'del /s /q /f %systemdrive%\\*._mp',
            'del /s /q /f %systemdrive%\\*.log',
            'del /s /q /f %systemdrive%\\*.gid',
            'del /s /q /f %systemdrive%\\*.chk',
            'del /s /q /f %systemdrive%\\*.old',
            'del /s /q /f %systemdrive%\\recycled\\*.*',
            'del /s /q /f %systemdrive%\\$Recycle.Bin\\*.*',
            'del /s /q /f %windir%\\*.bak',
            'del /s /q /f %windir%\\prefetch\\*.*',
            'del /s /q /f %LocalAppData%\\Microsoft\\Windows\\Explorer\\thumbcache_*.db',
            'del /s /q /f %LocalAppData%\\Microsoft\\Windows\\Explorer\\*.db',
            'del /f %SystemRoot%\\Logs\\CBS\\CBS.log',
            'del /f %SystemRoot%\\Logs\\DISM\\DISM.log',
            'rd /s /q c:\\windows\\tempor~1',
            'rd /s /q c:\\windows\\temp',
            'rd /s /q c:\\windows\\tmp',
            'rd /s /q c:\\windows\\ff*.tmp',
            'rd /s /q c:\\windows\\history',
            'rd /s /q c:\\windows\\cookies',
            'rd /s /q c:\\windows\\recent',
            'rd /s /q c:\\windows\\spool\\printers'
        ]

        processes = []
        for cmd in commands:
            processes.append(subprocess.Popen(cmd, shell=True))

        
        for process in processes:
            process.wait()

        
        subprocess.run('powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'DONE!\')"', shell=True)

    def win32(self):  
        commands = [
            r'Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "26" /f',
            r'Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "26" /f'
        ]

        for command in commands:
            subprocess.run(command, shell=True, check=True)

       
        subprocess.run('powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show(\'DONE!\')"', shell=True)

    def install(self):
        try:
            os.makedirs(r"C:\AV1\NvidiaProfileInspector")
        except FileExistsError:
           
            pass

        
        subprocess.run(['curl', '-g', '-k', '-L', '-#', '-o', '%temp%\\nvidiaProfileInspector.zip', 'https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip'])

        
        subprocess.run(['powershell', '-NoProfile', 'Expand-Archive', '%temp%\\nvidiaProfileInspector.zip', '-DestinationPath', 'C:\\AV1\\NvidiaProfileInspector\\'])

        
        subprocess.run(['curl', '-g', '-k', '-L', '-#', '-o', 'C:\\AV1\\NvidiaProfileInspector\\ruizz.nip', 'https://cdn.discordapp.com/attachments/1182472890684276766/1241203021204164649/av1.nip?ex=664957e4&is=66480664&hm=fd6f5c791cb87f15a8512a041c9c97e9e668a966fb2b550f2448fa7f7f589639&'])

        
        exe_path = r'C:\AV1\NvidiaProfileInspector\nvidiaProfileInspector.exe'
        nip_path = r'C:\AV1\NvidiaProfileInspector\av1.nip'
        subprocess.Popen([exe_path, nip_path])

    def debloat(self):
        subprocess.run(['powershell', '-Command', 'iwr -useb https://christitus.com/win | iex'], check=True)
        pass

    def wallpaper(self):
        
        import subprocess

        
        subprocess.run(['curl', '-g', '-k', '-L', '-#', '-o', 'C:\\AV1.png', 'https://drive.google.com/uc?export=download&id=16Eu7SkG8lfW8R6ibU7lg1-mnCF-I6QOU'])
        
       
        subprocess.run(['reg', 'add', 'HKCU\\control panel\\desktop', '/v', 'wallpaper', '/t', 'REG_SZ', '/d', 'C:\\AV1.png', '/f'])
        subprocess.run(['reg', 'delete', 'HKCU\\Software\\Microsoft\\Internet Explorer\\Desktop\\General', '/v', 'WallpaperStyle', '/f'])
        
        
        subprocess.run(['RUNDLL32.EXE', 'user32.dll,UpdatePerUserSystemParameters'])
        

if __name__ == "__main__":
    
    root = tk.Tk()
    app = DownloadApp(root); app.run()
    style = ttk.Style(root)
    style.configure("Custom.TButton", font=("Akira Expanded", 16))
    root.mainloop()
    
