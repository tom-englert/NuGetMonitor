using NuGetMonitor.View.Monitor;
using System.Windows.Input;
using TomsToolbox.Essentials;
using TomsToolbox.Wpf;

namespace NuGetMonitor.Abstractions;

internal static class PlatformAbstractions
{
    static PlatformAbstractions()
    {
    }

    public static void OpenDocument(string path)
    {
        throw new NotImplementedException();
    }

    public static async Task<ICollection<string>> GetProjectFilePaths()
    {
        throw new NotImplementedException();
    }

    public static event EventHandler? SolutionOpened;

    public static event EventHandler? SolutionClosed;

    public static void ShowPackageManager()
    {
        throw new NotImplementedException();
    }

    public static async Task ShowInfoBar(string message)
    {
        throw new NotImplementedException();
    }

    public static string? GetCurrentSolutionFilePath()
    {
        throw new NotImplementedException();
    }

    public static void FireAndForget(this System.Threading.Tasks.Task task, bool logOnFailure = true)
    {
        task.ContinueWith(delegate { }, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default).Forget();
    }

    public static void Forget(this Task? task)
    {
    }

    public static void CloseInfoBars()
    {
        throw new NotImplementedException();
    }
}
