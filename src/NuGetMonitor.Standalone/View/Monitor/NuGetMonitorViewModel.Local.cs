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
}
