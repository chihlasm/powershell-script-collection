using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

namespace MSPTroubleshootingWorkbench.Launcher
{
    internal static class MSPWorkbenchLauncher
    {
        private const string EntryPointScript = "Start-MSPTroubleshootingWorkbench.ps1";

        [STAThread]
        private static int Main()
        {
            string exeDirectory = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory);
            string scriptPath = ResolveEntryPointPath(exeDirectory);

            if (String.IsNullOrEmpty(scriptPath))
            {
                MessageBox.Show(
                    "Unable to find " + EntryPointScript + " next to MSPWorkbench.exe or in the parent folder.",
                    "MSP Troubleshooting Workbench",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return 2;
            }

            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath + "\"",
                    WorkingDirectory = exeDirectory,
                    UseShellExecute = false
                };

                Process.Start(startInfo);
                return 0;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Unable to start the MSP Troubleshooting Workbench.\r\n\r\n" + ex.Message,
                    "MSP Troubleshooting Workbench",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return 1;
            }
        }

        private static string ResolveEntryPointPath(string exeDirectory)
        {
            DirectoryInfo exeDirectoryInfo = new DirectoryInfo(exeDirectory);

            string sameFolderPath = Path.GetFullPath(Path.Combine(exeDirectoryInfo.FullName, EntryPointScript));
            if (File.Exists(sameFolderPath))
            {
                return sameFolderPath;
            }

            DirectoryInfo parentDirectory = exeDirectoryInfo.Parent;
            if (parentDirectory == null)
            {
                return String.Empty;
            }

            string parentFolderPath = Path.GetFullPath(Path.Combine(parentDirectory.FullName, EntryPointScript));
            if (File.Exists(parentFolderPath))
            {
                return parentFolderPath;
            }

            return String.Empty;
        }
    }
}
