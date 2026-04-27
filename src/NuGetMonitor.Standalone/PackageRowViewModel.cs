using CommunityToolkit.Mvvm.ComponentModel;
using NuGet.Versioning;
using NuGetMonitor.Model.Models;
using NuGetMonitor.Model.Services;

using Package = NuGetMonitor.Model.Models.Package;

namespace NuGetMonitor.Standalone;

public sealed partial class PackageRowViewModel : ObservableObject
{
    [ObservableProperty]
    private Package? _package;

    [ObservableProperty]
    private NuGetVersion? _selectedVersion;

    [ObservableProperty]
    private PackageInfo? _packageInfo;

    [ObservableProperty]
    private bool _isLoading = true;

    public PackageRowViewModel(PackageReference packageReference, string installedVersion)
    {
        PackageReference = packageReference;
        InstalledVersion = installedVersion;
    }

    public PackageReference PackageReference { get; }

    public string PackageId => PackageReference.Id;

    public string InstalledVersion { get; }

    public string? Issues => PackageInfo?.Issues;

    public bool IsUpdateAvailable =>
        SelectedVersion is not null &&
        NuGetVersion.TryParse(InstalledVersion, out var current) &&
        SelectedVersion > current;

    public async Task LoadAsync()
    {
        try
        {
            Package = await NuGetService.GetPackage(PackageReference.Id);

            var versions = Package?.Versions ?? [];

            if (PackageReference is { PinnedRange: { } range })
                versions = versions.Where(range.Satisfies).ToArray();

            SelectedVersion = NuGetVersion.TryParse(InstalledVersion, out var current)
                ? versions.FirstOrDefault(v => !v.IsPrerelease && v >= current)
                  ?? versions.FirstOrDefault()
                : null;

            var packageIdentity = PackageReference.FindBestMatch(versions);
            PackageInfo = await NuGetService.GetPackageInfo(packageIdentity);

            OnPropertyChanged(nameof(Issues));
            OnPropertyChanged(nameof(IsUpdateAvailable));
        }
        catch (OperationCanceledException)
        {
            // session cancelled
        }
        finally
        {
            IsLoading = false;
        }
    }
}
