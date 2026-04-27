using Microsoft.Build.Construction;

namespace NuGetMonitor.Abstractions;

internal static class PlatformAbstractions
{
    private static string? _solutionPath;

    public static void OpenSolution(string? solutionFilePath)
    {
        if (_solutionPath is not null)
        {
            SolutionClosed?.Invoke(null, EventArgs.Empty);
        }

        _solutionPath = solutionFilePath;

        if (solutionFilePath is not null)
        {
            SolutionOpened?.Invoke(null, EventArgs.Empty);
        }
    }

    public static void OpenDocument(string path)
    {
        // In standalone mode, we could open files with the default application
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
        catch
        {
            // Ignore errors if file cannot be opened
        }
    }

    public static async Task<ICollection<string>> GetProjectFilePaths()
    {
        if (string.IsNullOrEmpty(_solutionPath) || !File.Exists(_solutionPath))
        {
            return [];
        }

        return await Task.Run(ICollection<string> () =>
        {
            try
            {
                var solutionFile = SolutionFile.Parse(_solutionPath);

                var solutionDirectory = Path.GetDirectoryName(_solutionPath) ?? string.Empty;

                var projectPaths = solutionFile.ProjectsInOrder
                    .Where(p => p.ProjectType == SolutionProjectType.KnownToBeMSBuildFormat)
                    .Select(p => Path.GetFullPath(Path.Combine(solutionDirectory, p.RelativePath)))
                    .Where(File.Exists)
                    .ToArray();

                return projectPaths;
            }
            catch
            {
                return [];
            }
        });
    }

    public static event EventHandler? SolutionOpened;

    public static event EventHandler? SolutionClosed;

    public static async Task ShowInfoBar(string message)
    {
        // In standalone mode, we could show this in a message box or status bar
        // For now, just log to console
        await Task.CompletedTask;
        Console.WriteLine($"InfoBar: {message}");
    }

    public static void FireAndForget(this System.Threading.Tasks.Task task, bool logOnFailure = true)
    {
        task.ContinueWith(delegate { }, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default).Forget();
    }

    public static void Forget(this Task? task)
    {
    }
}
