using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Community.VisualStudio.Toolkit;
using DataGridExtensions;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell.Interop;
using NuGetMonitor.Abstractions;
using NuGetMonitor.Services;

namespace NuGetMonitor.View.Monitor;

partial class NuGetMonitorViewModel
{
    public static ICommand ShowDependencyTreeCommand => new DelegateCommand(ShowDependencyTree);

    public static ICommand ShowNuGetPackageManagerCommand => new DelegateCommand(() => PlatformAbstractions.ShowPackageManager());

    private static void ShowDependencyTree()
    {
        NuGetMonitorCommands.Instance?.ShowDependencyTreeToolWindow();
    }

    public ICommand RefreshCommand => new DelegateCommand<DataGrid>(Refresh);

    private void Refresh(DataGrid dataGrid)
    {
        dataGrid.GetFilter().Clear();

        MonitorService.CheckForUpdates();

        Load().FireAndForget();
    }

    private static async Task<bool> ShowNoYesMessageBox(string line1, string line2)
    {
        var response = await VS.MessageBox.ShowAsync(
            line1,
            line2,
            OLEMSGICON.OLEMSGICON_WARNING, OLEMSGBUTTON.OLEMSGBUTTON_YESNO, OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_SECOND);

        if (response != VSConstants.MessageBoxResult.IDYES)
            return false;

        return true;
    }
}

