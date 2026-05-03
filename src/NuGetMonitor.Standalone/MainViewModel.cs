using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Input;
using NuGetMonitor.Model.Services;
using NuGetMonitor.Services;
using NuGetMonitor.View.Monitor;

namespace NuGetMonitor;

internal sealed partial class MainViewModel : INotifyPropertyChanged
{
    private readonly LoggerSink _loggerSink;
    private readonly InfoBarService _infoBarService;
    private readonly MonitorService _monitorService;

    public string? SolutionPath { get; private set; }

    public string? StatusMessage { get; private set; }

    public object? NuGetMonitorViewModel { get; } = new NuGetMonitorViewModel();

    public ReadOnlyObservableCollection<LogEntry> LogEntries => _loggerSink.LogEntries;

    public ReadOnlyObservableCollection<InfoBarMessage> InfoBarMessages => _infoBarService.Messages;

    public ICommand BrowseCommand => new DelegateCommand(() => BrowseRequested?.Invoke(this, EventArgs.Empty));

    internal EventHandler? BrowseRequested;

    public MainViewModel()
    {
        _loggerSink = new LoggerSink();
        LoggerService.AddSink(_loggerSink);

        _infoBarService = new InfoBarService();

        _monitorService = new MonitorService(_infoBarService);
        _monitorService.RegisterEventHandlers();
    }

    internal async Task LoadSolutionAsync(string? path)
    {
        SolutionPath = path;
        StatusMessage = string.IsNullOrEmpty(path) ? "No solution loaded" : $"Loaded: {path}";

        PlatformAbstractions.OpenSolution(path);

        await Task.CompletedTask;
    }

    public void Dispose()
    {
        _monitorService.UnregisterEventHandlers();
    }
}
