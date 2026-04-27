using System.ComponentModel;
using System.Windows.Input;
using NuGetMonitor.View.Monitor;

namespace NuGetMonitor;

internal sealed partial class MainViewModel : INotifyPropertyChanged
{
    public bool IsLoading { get; private set; }

    public string? SolutionPath { get; private set; }

    public string? StatusMessage { get; private set; }

    public object? NuGetMonitorViewModel { get; } = new NuGetMonitorViewModel();

    public ICommand BrowseCommand => new DelegateCommand(() => BrowseRequested?.Invoke(this, EventArgs.Empty));

    internal EventHandler? BrowseRequested;

    internal async Task LoadSolutionAsync(string? path)
    {
        SolutionPath = path;
        StatusMessage = string.IsNullOrEmpty(path) ? "No solution loaded" : $"Loaded: {path}";

        PlatformAbstractions.OpenSolution(path);

        await Task.CompletedTask;
    }
}
