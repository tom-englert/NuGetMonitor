using Avalonia.Platform.Storage;
using PropertyChanged;

namespace NuGetMonitor.Standalone;

[DoNotNotify]
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private MainViewModel? ViewModel => DataContext as MainViewModel;

    // Called by the BrowseCommand relay — we intercept it here because file dialogs need a Window reference.
    protected override void OnLoaded(Avalonia.Interactivity.RoutedEventArgs e)
    {
        base.OnLoaded(e);

        if (ViewModel is { } vm)
            vm.BrowseRequested += OnBrowseRequested;
    }

    protected override void OnUnloaded(Avalonia.Interactivity.RoutedEventArgs e)
    {
        base.OnUnloaded(e);

        if (ViewModel is { } vm)
            vm.BrowseRequested -= OnBrowseRequested;
    }

    private void OnBrowseRequested(object? sender, EventArgs e)
    {
        OpenSolutionFileAsync().ConfigureAwait(false);
    }

    private async Task OpenSolutionFileAsync()
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Open Solution File",
            AllowMultiple = false,
            FileTypeFilter =
            [
                new FilePickerFileType("Visual Studio Solution") { Patterns = ["*.sln"] },
                new FilePickerFileType("All files") { Patterns = ["*"] }
            ]
        });

        if (files.Count > 0)
        {
            var path = files[0].TryGetLocalPath();
            if (!string.IsNullOrEmpty(path) && ViewModel is { } vm)
                await vm.LoadSolutionAsync(path);
        }
    }
}
