using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Build.Construction;
using NuGetMonitor.Model.Services;

namespace NuGetMonitor.Standalone;

public sealed partial class MainViewModel : ObservableObject
{
    [ObservableProperty]
    private string? _solutionPath;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _statusMessage;

    public ObservableCollection<PackageRowViewModel> Packages { get; } = new();

    public event EventHandler? BrowseRequested;

    public MainViewModel(string? solutionPath)
    {
        _solutionPath = solutionPath;

        if (!string.IsNullOrWhiteSpace(solutionPath))
            LoadAsync().ConfigureAwait(false);
    }

    [RelayCommand]
    private void Browse()
    {
        BrowseRequested?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        await LoadAsync();
    }

    public async Task LoadSolutionAsync(string path)
    {
        SolutionPath = path;
        await LoadAsync();
    }

    private async Task LoadAsync()
    {
        if (string.IsNullOrWhiteSpace(SolutionPath) || !File.Exists(SolutionPath))
        {
            StatusMessage = "No solution file selected.";
            return;
        }

        if (IsLoading)
            return;

        try
        {
            IsLoading = true;
            StatusMessage = "Loading…";
            Packages.Clear();

            var solutionFolder = Path.GetDirectoryName(SolutionPath);

            NuGetService.Reset(solutionFolder);
            ProjectService.ClearCache();

            var projectPaths = GetProjectPaths(SolutionPath);

            var packageReferences = await ProjectService.GetPackageReferences(projectPaths);

            var rows = packageReferences
                .GroupBy(item => item.Identity)
                .Select(group =>
                {
                    var key = group.Key;
                    var installed = key.VersionRange.OriginalString;
                    return new PackageRowViewModel(key, installed);
                })
                .ToArray();

            foreach (var row in rows)
                Packages.Add(row);

            StatusMessage = $"Loaded {rows.Length} packages.";

            IsLoading = false;

            await Task.WhenAll(rows.Select(r => r.LoadAsync()));

            StatusMessage = $"{rows.Length} packages — {rows.Count(r => r.IsUpdateAvailable)} update(s) available.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private static string[] GetProjectPaths(string solutionPath)
    {
        var solution = SolutionFile.Parse(solutionPath);
        var solutionDir = Path.GetDirectoryName(solutionPath) ?? string.Empty;

        return solution.ProjectsInOrder
            .Where(p => p.ProjectType == SolutionProjectType.KnownToBeMSBuildFormat)
            .Select(p => Path.IsPathRooted(p.AbsolutePath) ? p.AbsolutePath : Path.Combine(solutionDir, p.RelativePath))
            .Where(File.Exists)
            .ToArray();
    }
}
