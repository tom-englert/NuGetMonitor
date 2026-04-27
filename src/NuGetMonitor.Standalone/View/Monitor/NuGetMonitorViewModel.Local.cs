using System.Text;
using System.Windows.Input;
using TomsToolbox.Essentials;

namespace NuGetMonitor.View.Monitor;

partial class NuGetMonitorViewModel
{
    public ICommand RefreshCommand => new DelegateCommand<DataGrid?>(Refresh);

    private void Refresh(DataGrid? dataGrid)
    {
        Load().FireAndForget();
    }

    private static async Task<bool> ShowNoYesMessageBox(string line1, string line2)
    {
        // In standalone mode, we'll default to Yes for now
        // Could be enhanced with a proper dialog implementation
        await Task.CompletedTask;
        Console.WriteLine($"Question: {line1} - {line2}");
        return true;
    }

    private bool CanCopyIssueDetails()
    {
        return Packages?.Any(p => p.PackageInfo?.HasIssues ?? false) == true;
    }

    private async void CopyIssueDetails()
    {
        if (Packages is null)
            return;

        var text = new StringBuilder();

        foreach (var package in Packages)
        {
            package.PackageInfo?.AppendIssueDetails(text);
        }

        // Copy to clipboard
        await CopyToClipboardAsync(text.ToString());
    }

    private static async Task CopyToClipboardAsync(string text)
    {
        // TODO: Implement clipboard copy for Avalonia
        // The Clipboard API in Avalonia 12 may differ from the WPF version
        await Task.CompletedTask;
        Console.WriteLine("Clipboard copy not yet implemented - Issue details:");
        Console.WriteLine(text);
    }
}
