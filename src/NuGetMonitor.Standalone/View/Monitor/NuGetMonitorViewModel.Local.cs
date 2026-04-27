using System.Text;
using System.Windows.Input;
using TomsToolbox.Wpf;

namespace NuGetMonitor.View.Monitor;

partial class NuGetMonitorViewModel
{
    public ICommand RefreshCommand => new DelegateCommand<DataGrid>(Refresh);

    private void Refresh(DataGrid dataGrid)
    {
        Load().FireAndForget();
    }

    private static async Task<bool> ShowNoYesMessageBox(string line1, string line2)
    {
        throw new NotImplementedException();
    }

    private bool CanCopyIssueDetails()
    {
        return Packages?.Any(p => p.PackageInfo?.HasIssues ?? false) == true;
    }

    private void CopyIssueDetails()
    {
        if (Packages is null)
            return;

        var text = new StringBuilder();

        foreach (var package in Packages)
        {
            package.PackageInfo?.AppendIssueDetails(text);
        }

        throw new NotImplementedException();
        // Clipboard.SetText(text.ToString());
    }
}

