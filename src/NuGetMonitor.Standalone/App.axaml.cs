using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace NuGetMonitor.Standalone;

public class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var args = desktop.Args ?? [];
            var solutionPath = args.Length > 0 ? args[0] : null;

            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainViewModel(solutionPath)
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
