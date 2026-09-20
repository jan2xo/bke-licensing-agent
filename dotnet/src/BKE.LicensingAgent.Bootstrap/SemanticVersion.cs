using System.Text.RegularExpressions;

namespace BKE.LicensingAgent.Bootstrap;

internal sealed record SemanticVersion(int Major, int Minor, int Patch, string? PreRelease) : IComparable<SemanticVersion>
{
    private static readonly Regex Pattern = new(
        "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\\+[0-9A-Za-z.-]+)?$",
        RegexOptions.CultureInvariant);

    internal static SemanticVersion Parse(string value)
    {
        var match = Pattern.Match(value);
        if (!match.Success) throw new InvalidDataException("invalid Agent semantic version");
        return new SemanticVersion(
            int.Parse(match.Groups[1].Value),
            int.Parse(match.Groups[2].Value),
            int.Parse(match.Groups[3].Value),
            match.Groups[4].Success ? match.Groups[4].Value : null);
    }

    public int CompareTo(SemanticVersion? other)
    {
        if (other is null) return 1;
        var core = Major.CompareTo(other.Major);
        if (core == 0) core = Minor.CompareTo(other.Minor);
        if (core == 0) core = Patch.CompareTo(other.Patch);
        if (core != 0) return core;
        if (PreRelease is null) return other.PreRelease is null ? 0 : 1;
        if (other.PreRelease is null) return -1;

        var left = PreRelease.Split('.');
        var right = other.PreRelease.Split('.');
        for (var index = 0; index < Math.Max(left.Length, right.Length); index++)
        {
            if (index >= left.Length) return -1;
            if (index >= right.Length) return 1;
            var leftNumeric = int.TryParse(left[index], out var leftNumber);
            var rightNumeric = int.TryParse(right[index], out var rightNumber);
            int compared;
            if (leftNumeric && rightNumeric) compared = leftNumber.CompareTo(rightNumber);
            else if (leftNumeric) compared = -1;
            else if (rightNumeric) compared = 1;
            else compared = string.CompareOrdinal(left[index], right[index]);
            if (compared != 0) return compared;
        }
        return 0;
    }
}
