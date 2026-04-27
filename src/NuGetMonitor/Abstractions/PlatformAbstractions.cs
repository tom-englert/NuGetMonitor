using Community.VisualStudio.Toolkit;
using Microsoft.VisualStudio.Shell;
using NuGetMonitor.Model.Services;
using NuGetMonitor.Services;
using NuGetMonitor.View.Monitor;
using TomsToolbox.Essentials;

namespace NuGetMonitor.Abstractions;

internal static class PlatformAbstractions
{
    static PlatformAbstractions()
    {
        VS.Events.SolutionEvents.OnAfterOpenSolution += SolutionEvents_OnAfterOpenSolution;
        VS.Events.SolutionEvents.OnAfterCloseSolution += SolutionEvents_OnAfterCloseSolution;
        VS.Events.ShellEvents.ShutdownStarted += NuGetService.Shutdown;
    }

    public static void OpenDocument(string path)
    {
        VS.Documents.OpenAsync(path).FireAndForget();
    }

    public static string? GetCurrentSolutionFilePath()
    {
        return VS.Solutions.GetCurrentSolution()?.FullPath;
    }

    public static async Task<ICollection<string>> GetProjectFilePaths()
    {
        var projects = await VS.Solutions.GetAllProjectsAsync();

        var filePaths = projects.Select(project => project.FullPath)
            .ExceptNullItems()
            .ToArray();

        return filePaths;
    }

    private static void SolutionEvents_OnAfterCloseSolution()
    {
        SolutionClosed?.Invoke(null, EventArgs.Empty);
    }

    private static void SolutionEvents_OnAfterOpenSolution(Solution? obj)
    {
        SolutionOpened?.Invoke(null, EventArgs.Empty);
    }

    public static event EventHandler? SolutionOpened;

    public static event EventHandler? SolutionClosed;

    public static void ShowPackageManager()
    {
        VS.Commands.ExecuteAsync("Tools.ManageNuGetPackagesForSolution").FireAndForget();
    }

    public static async Task ShowInfoBar(string message)
    {
        var model = new InfoBarModel(message);
        var infoBar = await VS.InfoBar.CreateAsync(NuGetMonitorToolWindow.Id, model).ConfigureAwait(true) ?? throw new InvalidOperationException("Failed to create the info bar");
        await infoBar.TryShowInfoBarUIAsync().ConfigureAwait(true);

        await Task.Delay(TimeSpan.FromSeconds(5)).ConfigureAwait(true);

        infoBar.Close();
    }

    public static void CloseInfoBars()
    {
        InfoBarService.CloseInfoBars();
    }
}
