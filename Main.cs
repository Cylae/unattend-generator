using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace Schneegans.Unattend;

/// <summary>
/// Represents the different configuration passes in the Windows Setup process.
/// </summary>
public enum Pass
{
  /// <summary>
  /// The offlineServicing configuration pass is used to apply updates, drivers, and language packs to a Windows image offline.
  /// </summary>
  offlineServicing,
  /// <summary>
  /// The windowsPE configuration pass is used to configure Windows Preinstallation Environment (WinPE) settings.
  /// </summary>
  windowsPE,
  /// <summary>
  /// The generalize configuration pass is used to create a reference Windows image that can be captured and applied to other computers.
  /// </summary>
  generalize,
  /// <summary>
  /// The specialize configuration pass is used to apply computer-specific settings to a Windows installation.
  /// </summary>
  specialize,
  /// <summary>
  /// The auditSystem configuration pass is used to add drivers and applications to a Windows installation in audit mode.
  /// </summary>
  auditSystem,
  /// <summary>
  /// The auditUser configuration pass is used to apply user-specific settings to a Windows installation in audit mode.
  /// </summary>
  auditUser,
  /// <summary>
  /// The oobeSystem configuration pass is used to apply settings to a Windows installation before the Out-of-Box Experience (OOBE) is complete.
  /// </summary>
  oobeSystem
}

/// <summary>
/// Specifies the recovery mode for the Windows installation.
/// </summary>
public enum RecoveryMode
{
  /// <summary>
  /// No recovery option is configured.
  /// </summary>
  None,
  /// <summary>
  /// A recovery folder is created.
  /// </summary>
  Folder,
  /// <summary>
  /// A dedicated recovery partition is created.
  /// </summary>
  Partition
}

/// <summary>
/// Specifies the partition layout for the disk.
/// </summary>
public enum PartitionLayout
{
  /// <summary>
  /// Master Boot Record (MBR) partition layout.
  /// </summary>
  MBR,
  /// <summary>
  /// GUID Partition Table (GPT) partition layout.
  /// </summary>
  GPT
}

/// <summary>
/// Specifies the processor architecture.
/// </summary>
public enum ProcessorArchitecture
{
  /// <summary>
  /// 32-bit (x86) processor architecture.
  /// </summary>
  x86,
  /// <summary>
  /// 64-bit (amd64) processor architecture.
  /// </summary>
  amd64,
  /// <summary>
  /// ARM64 processor architecture.
  /// </summary>
  arm64
}

/// <summary>
/// Specifies the mode for express settings.
/// </summary>
public enum ExpressSettingsMode
{
  /// <summary>
  /// The user will be prompted to configure express settings.
  /// </summary>
  Interactive,
  /// <summary>
  /// All express settings will be enabled.
  /// </summary>
  EnableAll,
  /// <summary>
  /// All express settings will be disabled.
  /// </summary>
  DisableAll
}

/// <summary>
/// Specifies the appearance of the search box on the taskbar.
/// </summary>
public enum TaskbarSearchMode
{
  /// <summary>
  /// The search box is hidden.
  /// </summary>
  Hide = 0,
  /// <summary>
  /// Only the search icon is shown.
  /// </summary>
  Icon = 1,
  /// <summary>
  /// The full search box is shown.
  /// </summary>
  Box = 2,
  /// <summary>
  /// The search box is shown with a label.
  /// </summary>
  Label = 3
}

/// <summary>
/// Represents a component and the pass in which it should be configured.
/// </summary>
/// <param name="Component">The name of the component.</param>
/// <param name="Pass">The configuration pass.</param>
public record struct ComponentAndPass(
  string Component,
  Pass Pass
);

/// <summary>
/// Defines the configuration for a command to be executed during the Windows Setup process.
/// </summary>
internal abstract class CommandConfig
{
  /// <summary>
  /// A command to be executed in the windowsPE pass.
  /// </summary>
  public readonly static CommandConfig WindowsPE = new WindowsPECommandConfig();
  /// <summary>
  /// A command to be executed in the specialize pass.
  /// </summary>
  public readonly static CommandConfig Specialize = new SpecializeCommandConfig();
  /// <summary>
  /// A command to be executed in the oobeSystem pass.
  /// </summary>
  public readonly static CommandConfig Oobe = new OobeCommandConfig();

  /// <summary>
  /// Creates the XML element for the command.
  /// </summary>
  /// <param name="doc">The XML document.</param>
  /// <param name="ns">The namespace manager.</param>
  /// <returns>The created XML element.</returns>
  public abstract XmlElement CreateElement(XmlDocument doc, XmlNamespaceManager ns);

  /// <summary>
  /// Inserts a command using this markup:
  /// <code>
  /// &lt;settings pass=&quot;windowsPE&quot;&gt;
  ///   &lt;component name=&quot;Microsoft-Windows-Setup&quot;&gt;
  ///     &lt;RunSynchronous&gt;
  ///       &lt;RunSynchronousCommand&gt;
  ///         &lt;Path&gt;
  /// </code>
  /// </summary>
  private class WindowsPECommandConfig : CommandConfig
  {
    public override XmlElement CreateElement(XmlDocument doc, XmlNamespaceManager ns)
    {
      var container = Util.GetOrCreateElement(Pass.windowsPE, "Microsoft-Windows-Setup", "RunSynchronous", doc, ns);
      var outer = Util.NewElement("RunSynchronousCommand", container, doc, ns);
      return Util.NewElement("Path", outer, doc, ns);
    }
  }

  /// <summary>
  /// Inserts a command using this markup:
  /// <code>
  /// &lt;settings pass=&quot;specialize&quot;&gt;
  ///   &lt;component name=&quot;Microsoft-Windows-Deployment&quot;&gt;
  ///     &lt;RunSynchronous&gt;
  ///       &lt;RunSynchronousCommand&gt;
  ///         &lt;Path&gt;
  /// </code>
  /// </summary>
  private class SpecializeCommandConfig : CommandConfig
  {
    public override XmlElement CreateElement(XmlDocument doc, XmlNamespaceManager ns)
    {
      var container = Util.GetOrCreateElement(Pass.specialize, "Microsoft-Windows-Deployment", "RunSynchronous", doc, ns);
      var outer = Util.NewElement("RunSynchronousCommand", container, doc, ns);
      return Util.NewElement("Path", outer, doc, ns);
    }
  }

  /// <summary>
  /// Inserts a command using this markup:
  /// <code>
  /// &lt;settings pass=&quot;oobeSystem&quot;&gt;
  ///   &lt;component name=&quot;Microsoft-Windows-Shell-Setup&quot;&gt;
  ///     &lt;FirstLogonCommands&gt;
  ///       &lt;SynchronousCommand&gt;
  ///         &lt;CommandLine&gt;
  /// </code>
  /// </summary>
  private class OobeCommandConfig : CommandConfig
  {
    public override XmlElement CreateElement(XmlDocument doc, XmlNamespaceManager ns)
    {
      var container = Util.GetOrCreateElement(Pass.oobeSystem, "Microsoft-Windows-Shell-Setup", "FirstLogonCommands", doc, ns);
      var outer = Util.NewElement("SynchronousCommand", container, doc, ns);
      return Util.NewElement("CommandLine", outer, doc, ns);
    }
  }
}

/// <summary>
/// Appends commands to the unattend.xml file.
/// </summary>
/// <param name="doc">The XML document.</param>
/// <param name="ns">The namespace manager.</param>
/// <param name="config">The command configuration.</param>
internal class CommandAppender(XmlDocument doc, XmlNamespaceManager ns, CommandConfig config)
{
  /// <summary>
  /// Appends a single command.
  /// </summary>
  /// <param name="value">The command to append.</param>
  public void Append(string value)
  {
    config.CreateElement(doc, ns).InnerText = value;
  }

  /// <summary>
  /// Appends a collection of commands.
  /// </summary>
  /// <param name="values">The commands to append.</param>
  public void Append(IEnumerable<string> values)
  {
    foreach (string value in values)
    {
      Append(value);
    }
  }
}

/// <summary>
/// Builds various types of commands.
/// </summary>
/// <param name="hidePowerShellWindows">Whether to hide PowerShell windows.</param>
public class CommandBuilder(bool hidePowerShellWindows)
{
  /// <summary>
  /// Returns a raw command without any modification.
  /// </summary>
  /// <param name="command">The command.</param>
  /// <returns>The raw command.</returns>
  public string Raw(string command)
  {
    return command;
  }

  /// <summary>
  /// Wraps a command in <c>cmd.exe /c</c>.
  /// </summary>
  /// <param name="command">The command.</param>
  /// <returns>The wrapped command.</returns>
  public string ShellCommand(string command)
  {
    return $@"cmd.exe /c ""{command}""";
  }

  /// <summary>
  /// Creates a command to modify the Windows Registry.
  /// </summary>
  /// <param name="value">The arguments for <c>reg.exe</c>.</param>
  /// <returns>The full registry command.</returns>
  public string RegistryCommand(string value)
  {
    return $"reg.exe {value}";
  }

  /// <summary>
  /// Creates a PowerShell command.
  /// </summary>
  /// <param name="value">The PowerShell script to execute.</param>
  /// <returns>The full PowerShell command.</returns>
  public string PowerShellCommand(string value)
  {
    {
      const char quote = '"';
      if (value.Contains(quote))
      {
        throw new ArgumentException($"PowerShell command '{value}' must not contain '{quote}'.");
      }
    }
    {
      const char semicolon = ';';
      const char brace = '}';
      if (!value.EndsWith(semicolon) && !value.EndsWith(brace))
      {
        throw new ArgumentException($"PowerShell command '{value}' must end with either '{semicolon}' or '{brace}'.");
      }
    }
    return @$"powershell.exe -WindowStyle {(hidePowerShellWindows ? "Hidden" : "Normal")} -NoProfile -Command ""{value}""";
  }

  /// <summary>
  /// Creates a command to invoke a PowerShell script from a file.
  /// </summary>
  /// <param name="filepath">The path to the PowerShell script.</param>
  /// <returns>The full command.</returns>
  public string InvokePowerShellScript(string filepath)
  {
    return PowerShellCommand($"Get-Content -LiteralPath '{filepath}' -Raw | Invoke-Expression;");
  }

  /// <summary>
  /// Creates a command to invoke a VBScript file.
  /// </summary>
  /// <param name="filepath">The path to the VBScript file.</param>
  /// <returns>The full command.</returns>
  public string InvokeVBScript(string filepath)
  {
    return @$"cscript.exe //E:vbscript ""{filepath}""";
  }

  /// <summary>
  /// Creates a command to invoke a JScript file.
  /// </summary>
  /// <param name="filepath">The path to the JScript file.</param>
  /// <returns>The full command.</returns>
  public string InvokeJScript(string filepath)
  {
    return @$"cscript.exe //E:jscript ""{filepath}""";
  }

  /// <summary>
  /// Creates a series of commands to write lines to a file in the Windows PE environment.
  /// </summary>
  /// <param name="path">The path to the file.</param>
  /// <param name="lines">The lines to write.</param>
  /// <returns>A list of commands.</returns>
  public List<string> WriteToFilePE(string path, IEnumerable<string> lines)
  {
    static IEnumerable<string> Trim(IEnumerable<string> input)
    {
      return input
        .Select(l => l.Trim())
        .Where(l => l.Length > 0);
    }

    static IEnumerable<string> Escape(IEnumerable<string> input)
    {
      return input.Select(l => l
        .Replace("^", "^^")
        .Replace("&", "^&")
        .Replace("<", "^<")
        .Replace(">", "^>")
        .Replace("|", "^|")
        .Replace("%", "^%")
        .Replace(")", "^)")
        .Replace(@"""", @"^""")
      );
    }

    static IEnumerable<string> Echo(IEnumerable<string> input)
    {
      return input.Select(l => $"echo:{l}");
    }

    const int maxLineLength = 255;
    List<string> segments = [.. Echo(Escape(Trim(lines)))];
    List<string> result = [];

    while (segments.Count > 0)
    {
      string? prev = null, current = null;
      for (int take = 1; take <= segments.Count; take++)
      {
        current = $@"cmd.exe /c "">>""{path}"" ({segments.GetRange(0, take).JoinString('&')})""";
        if (current.Length > maxLineLength)
        {
          if (prev == null)
          {
            throw new ConfigurationException($"Line '{current}' is too long. You need to add line breaks to your input to make it shorter.");
          }
          else
          {
            result.Add(prev);
            segments.RemoveRange(0, take - 1);
            current = null;
            break;
          }
        }
        else
        {
          prev = current;
        }
      }
      if (current != null)
      {
        result.Add(current);
        break;
      }
    }

    return result;
  }
}

public class ConfigurationException(string? message) : Exception(message);

public record class Configuration(
  ILanguageSettings LanguageSettings,
  IAccountSettings AccountSettings,
  IPartitionSettings PartitionSettings,
  IInstallFromSettings InstallFromSettings,
  IDiskAssertionSettings DiskAssertionSettings,
  IEditionSettings EditionSettings,
  ILockoutSettings LockoutSettings,
  IPasswordExpirationSettings PasswordExpirationSettings,
  IProcessAuditSettings ProcessAuditSettings,
  IComputerNameSettings ComputerNameSettings,
  ITimeZoneSettings TimeZoneSettings,
  IWifiSettings WifiSettings,
  IWdacSettings WdacSettings,
  ImmutableHashSet<ProcessorArchitecture> ProcessorArchitectures,
  ImmutableDictionary<ComponentAndPass, string> Components,
  ImmutableList<Bloatware> Bloatwares,
  ExpressSettingsMode ExpressSettings,
  ScriptSettings ScriptSettings,
  Win32Settings Win32,
  IPESettings PESettings,
  bool BypassRequirementsCheck,
  bool BypassNetworkCheck,
  SystemSettings System,
  VisualSettings Visual,
  VirtualMachineSettings VirtualMachine,
  WingetSettings Winget
)
{
  public static Configuration Default => new(
    LanguageSettings: new InteractiveLanguageSettings(),
    AccountSettings: new InteractiveMicrosoftAccountSettings(),
    PartitionSettings: new InteractivePartitionSettings(),
    InstallFromSettings: new AutomaticInstallFromSettings(),
    DiskAssertionSettings: new SkipDiskAssertionSettings(),
    EditionSettings: new InteractiveEditionSettings(),
    LockoutSettings: new DefaultLockoutSettings(),
    PasswordExpirationSettings: new DefaultPasswordExpirationSettings(),
    ProcessAuditSettings: new DisabledProcessAuditSettings(),
    ComputerNameSettings: new RandomComputerNameSettings(),
    TimeZoneSettings: new ImplicitTimeZoneSettings(),
    WifiSettings: new InteractiveWifiSettings(),
    WdacSettings: new SkipWdacSettings(),
    ProcessorArchitectures: [ProcessorArchitecture.amd64],
    Components: ImmutableDictionary.Create<ComponentAndPass, string>(),
    Bloatwares: [],
    ExpressSettings: ExpressSettingsMode.DisableAll,
    ScriptSettings: new ScriptSettings(Scripts: [], RestartExplorer: false),
    Win32: new Win32Settings(
      WallpaperSettings: new DefaultWallpaperSettings(),
      LockScreenSettings: new DefaultLockScreenSettings(),
      ColorSettings: new DefaultColorSettings(),
      LockKeySettings: new SkipLockKeySettings(),
      StickyKeysSettings: new DefaultStickyKeysSettings()
    ),
    PESettings: new DefaultPESettings(),
    BypassRequirementsCheck: false,
    BypassNetworkCheck: false,
    System: new SystemSettings(
      EnableLongPaths: false,
      EnableRemoteDesktop: false,
      HardenSystemDriveAcl: false,
      AllowPowerShellScripts: false,
      DisableLastAccess: false,
      PreventAutomaticReboot: false,
      DisableDefender: false,
      DisableSac: false,
      DisableUac: false,
      DisableSmartScreen: false,
      DisableFastStartup: false,
      DisableSystemRestore: false,
      TurnOffSystemSounds: false,
      DisableAppSuggestions: false,
      PreventDeviceEncryption: false,
      DisableWindowsUpdate: false,
      DisablePointerPrecision: false,
      DeleteWindowsOld: false,
      DisableBingResults: false,
      UseConfigurationSet: false,
      HidePowerShellWindows: false,
      KeepSensitiveFiles: false,
      UseNarrator: false,
      DisableCoreIsolation: false,
      CompactOsMode: CompactOsModes.Default
    ),
    Visual: new VisualSettings(
      ClassicContextMenu: false,
      LeftTaskbar: false,
      HideTaskViewButton: false,
      ShowFileExtensions: false,
      ShowAllTrayIcons: false,
      HideFiles: HideModes.Hidden,
      HideEdgeFre: false,
      DisableEdgeStartupBoost: false,
      MakeEdgeUninstallable: false,
      LaunchToThisPC: false,
      ShowEndTask: false,
      DisableWidgets: false,
      TaskbarSearch: TaskbarSearchMode.Box,
      StartPinsSettings: new DefaultStartPinsSettings(),
      StartTilesSettings: new DefaultStartTilesSettings(),
      TaskbarIcons: new DefaultTaskbarIcons(),
      Effects: new DefaultEffects(),
      DesktopIcons: new DefaultDesktopIconSettings(),
      StartFolderSettings: new DefaultStartFolderSettings()
    ),
    VirtualMachine: new VirtualMachineSettings(
      VBoxGuestAdditions: false,
      VMwareTools: false,
      VirtIoGuestTools: false,
      ParallelsTools: false
    ),
    Winget: new WingetSettings(
      Packages: []
    )
  );
}

/// <summary>
/// Collects PowerShell commands that will be executed sequentially.
/// </summary>
public abstract class PowerShellSequence
{
  private bool needsExplorerRestart = false;
  private readonly List<string> commands = [];

  protected abstract string Activity();

  protected abstract string LogFile();

  public void Append(string command)
  {
    commands.Add(command);
  }

  public void InvokeFile(string file)
  {
    Append($"Get-Content -LiteralPath '{file}' -Raw | Invoke-Expression;");
  }

  public void RestartExplorer()
  {
    needsExplorerRestart = true;
  }

  public bool IsEmpty => commands.Count == 0;

  public string GetScript()
  {
    StringWriter writer = new();

    void WriteScriptBlock(string command)
    {
      writer.WriteLine("\t{");
      foreach (string line in Util.SplitLines(command))
      {
        writer.WriteLine($"\t\t{line}");
      }
      writer.WriteLine("\t};");
    }

    writer.WriteLine("$scripts = @(");
    foreach (string command in commands)
    {
      WriteScriptBlock(command);
    }
    if (needsExplorerRestart)
    {
      WriteScriptBlock(Util.StringFromResource("RestartExplorer.ps1"));
    }
    writer.WriteLine(");");
    writer.WriteLine();

    writer.WriteLine($$"""
      & {
        [float] $complete = 0;
        [float] $increment = 100 / $scripts.Count;
        foreach( $script in $scripts ) {
          Write-Progress -Activity '{{Activity()}} Do not close this window.' -PercentComplete $complete;
          '*** Will now execute command «{0}».' -f $(
            $str = $script.ToString().Trim() -replace '\s+', ' ';
            $max = 100;
            if( $str.Length -le $max ) {
              $str;
            } else {
              $str.Substring( 0, $max - 1 ) + '…';
            }
          );
          $start = [datetime]::Now;
          & $script;
          '*** Finished executing command after {0:0} ms.' -f [datetime]::Now.Subtract( $start ).TotalMilliseconds;
          "`r`n" * 3;
          $complete += $increment;
        }
      } *>&1 | Out-String -Stream >> "{{LogFile()}}";
      """);

    return writer.ToString();
  }
}

/// <summary>
/// Collects PowerShell commands that will be run whenever a user logs on for the first time.
/// </summary>
public class UserOnceSequence : PowerShellSequence
{
  protected override string Activity()
  {
    return "Running scripts to configure this user account.";
  }

  protected override string LogFile()
  {
    return @"$env:TEMP\UserOnce.log";
  }
}

/// <summary>
/// Collects PowerShell commands that will be run when the first user logs on after Windows has been installed.
/// </summary>
public class FirstLogonSequence : PowerShellSequence
{
  protected override string Activity()
  {
    return "Running scripts to finalize your Windows installation.";
  }

  protected override string LogFile()
  {
    return @"C:\Windows\Setup\Scripts\FirstLogon.log";
  }
}

/// <summary>
/// Collects PowerShell commands that modify the default user's registry hive.
/// </summary>
public class DefaultUserSequence : PowerShellSequence
{
  protected override string Activity()
  {
    return "Running scripts to modify the default user’’s registry hive.";
  }

  protected override string LogFile()
  {
    return @"C:\Windows\Setup\Scripts\DefaultUser.log";
  }
}

/// <summary>
/// Collects PowerShell commands that run in the system context, before user accounts are created.
/// </summary>
public class SpecializeSequence : PowerShellSequence
{
  protected override string Activity()
  {
    return "Running scripts to customize your Windows installation.";
  }

  protected override string LogFile()
  {
    return @"C:\Windows\Setup\Scripts\Specialize.log";
  }
}

public interface IKeyed
{
  string Id { get; }
}

public abstract class BloatwareStep(
  string[] appliesTo
)
{
  public ImmutableSortedSet<string> AppliesTo { get; } = [.. appliesTo];
}

public abstract class SelectorBloatwareStep(
  string[] appliesTo,
  string selector
) : BloatwareStep(appliesTo)
{
  public string Selector { get; } = selector;
}

public class PackageBloatwareStep(
  string[] appliesTo,
  string selector
) : SelectorBloatwareStep(appliesTo, selector);

public class CapabilityBloatwareStep(
  string[] appliesTo,
  string selector
) : SelectorBloatwareStep(appliesTo, selector);

public class OptionalFeatureBloatwareStep(
  string[] appliesTo,
  string selector
) : SelectorBloatwareStep(appliesTo, selector);

public class CustomBloatwareStep(
  string[] appliesTo
) : BloatwareStep(appliesTo);

public class Bloatware(
  string displayName,
  string? token,
  ImmutableList<BloatwareStep> steps
) : IKeyed
{
  public string DisplayName { get; } = displayName;

  public string Id { get; } = $"Remove{token ?? displayName.Replace(" ", "")}";

  public ImmutableList<BloatwareStep> Steps { get; } = steps;

  [JsonIgnore]
  public string? StepsLabel
  {
    get
    {
      IEnumerable<string> strings = Steps.SelectMany<BloatwareStep, string>(s => s switch
        {
          SelectorBloatwareStep sel => [sel.Selector],
          CustomBloatwareStep => [],
          _ => throw new NotImplementedException(),
        }
      );
      return strings.Any() ? string.Join(", ", strings) : null;
    }
  }
}

public class Component(
  string id,
  ImmutableSortedSet<Pass> passes
) : IKeyed
{
  public string Id { get; } = Validate(id);

  private static readonly Regex Pattern = new("^[a-z-]+$", RegexOptions.IgnoreCase);

  private static string Validate(string id)
  {
    if (!Pattern.IsMatch(id))
    {
      throw new ArgumentException($"ID '{id}' contains illegal characters.", nameof(id));
    }
    return id;
  }

  public ImmutableSortedSet<Pass> Passes { get; } = passes;

  public string Uri
  {
    get
    {
      string name = Id switch
      {
        "Microsoft-Windows-WDF-KernelLibrary" => "microsoft-windows-wdf-kernel-library",
        "Microsoft-Windows-MapControl-Desktop" => "microsoft-windows-mapcontrol",
        _ => Id.ToLowerInvariant(),
      };
      return $"https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/{name}";
    }
  }
}

public class WindowsEdition(
  string id,
  string displayName,
  string productKey,
  bool visible
) : IKeyed
{
  public string Id { get; } = id;

  public string DisplayName { get; } = displayName;

  public string ProductKey { get; } = productKey;

  public bool Visible = visible;
}

public class ImageLanguage(
  string id,
  string displayName
) : IKeyed
{
  public string Id { get; } = id;

  public string DisplayName { get; } = displayName;
}

public enum InputType
{
  Keyboard, IME
}

public class KeyboardIdentifier(
  string id,
  string displayName,
  InputType type
) : IKeyed
{
  public string Id { get; } = id;

  public string DisplayName { get; } = displayName;

  public InputType Type { get; } = type;
}

public class DesktopIcon(
  string id,
  string displayName,
  string guid
) : IKeyed, IComparable<DesktopIcon>
{
  public string Id { get; } = id;

  public string DisplayName { get; } = displayName;

  public string Guid { get; } = guid;

  public int CompareTo(DesktopIcon? other)
  {
    return Id.CompareTo(other?.Id);
  }
}

public class StartFolder(
  string displayName,
  byte[] bytes
) : IKeyed, IComparable<StartFolder>
{
  public string Id { get; } = displayName.Replace(" ", "");

  public string DisplayName { get; } = displayName;

  public byte[] Bytes { get; } = bytes;

  public int CompareTo(StartFolder? other)
  {
    return Id.CompareTo(other?.Id);
  }
}

public class TimeOffset(
  string id,
  string displayName
) : IKeyed
{
  public string Id { get; } = id;

  public string DisplayName { get; } = displayName;
}

public class GeoLocation(
  string id,
  string displayName
) : IKeyed
{
  public string Id { get; } = id;

  public string DisplayName { get; } = displayName;
}

public class KeyboardConverter(
  UnattendGenerator generator
) : JsonConverter<KeyboardIdentifier>
{
  public override bool CanWrite => false;

  public override KeyboardIdentifier? ReadJson(JsonReader reader, Type objectType, KeyboardIdentifier? existingValue, bool hasExistingValue, JsonSerializer serializer)
  {
    return reader.TokenType switch
    {
      JsonToken.String => generator.Lookup<KeyboardIdentifier>("" + reader.Value),
      JsonToken.Null => null,
      _ => throw new NotSupportedException(),
    };
  }

  public override void WriteJson(JsonWriter writer, KeyboardIdentifier? value, JsonSerializer serializer)
  {
    throw new NotImplementedException();
  }
}

public class GeoLocationConverter(
  UnattendGenerator generator
) : JsonConverter<GeoLocation>
{
  public override bool CanWrite => false;

  public override GeoLocation? ReadJson(JsonReader reader, Type objectType, GeoLocation? existingValue, bool hasExistingValue, JsonSerializer serializer)
  {
    return reader.TokenType switch
    {
      JsonToken.String => generator.Lookup<GeoLocation>("" + reader.Value),
      JsonToken.Null => null,
      _ => throw new NotSupportedException(),
    };
  }

  public override void WriteJson(JsonWriter writer, GeoLocation? value, JsonSerializer serializer)
  {
    throw new NotImplementedException();
  }
}

public class Base64Converter : JsonConverter<byte[]>
{
  public override bool CanWrite => false;

  public override byte[]? ReadJson(JsonReader reader, Type objectType, byte[]? existingValue, bool hasExistingValue, JsonSerializer serializer)
  {
    return reader.TokenType switch
    {
      JsonToken.String => Convert.FromBase64String("" + reader.Value),
      JsonToken.Null => null,
      _ => throw new NotSupportedException(),
    };
  }

  public override void WriteJson(JsonWriter writer, byte[]? value, JsonSerializer serializer)
  {
    throw new NotImplementedException();
  }
}

public class UserLocale(
  string id,
  string displayName,
  KeyboardIdentifier? keyboardLayout,
  string lcid,
  GeoLocation? geoLocation
) : IKeyed
{
  public string Id { get; } = id;

  public string DisplayName { get; } = displayName;

  public string LCID { get; } = lcid;

  public KeyboardIdentifier? KeyboardLayout { get; } = keyboardLayout;

  public GeoLocation? GeoLocation { get; } = geoLocation;
}

public static class Constants
{
  public const string UsersGroup = "Users";

  public const string AdministratorsGroup = "Administrators";

  public const string DefaultPassword = "";

  public const int RecoveryPartitionSize = 1000;

  public const int EspDefaultSize = 300;

  public static readonly string DiskpartScript = DiskModifier.GetCustomDiskpartScript();

  public const string MyNamespaceUri = "https://schneegans.de/windows/unattend-generator/";
}

public class UnattendGenerator
{
  public UnattendGenerator()
  {
    Bloatwares = LoadBloatwares();
    Components = LoadComponents();
    ImageLanguages = LoadImageLanguages();
    KeyboardIdentifiers = LoadKeyboardIdentifiers();
    GeoLocations = LoadGeoLocations();
    UserLocales = LoadUserLocales();
    WindowsEditions = LoadWindowsEditions();
    TimeOffsets = LoadTimeOffsets();
    DesktopIcons = LoadDesktopIcons();
    StartFolders = LoadStartFolders();

    VerifyData();
  }

  private IImmutableDictionary<string, Bloatware> LoadBloatwares()
  {
    string json = Util.StringFromResource("Bloatware.json");
    JsonSerializerSettings settings = new()
    {
      TypeNameHandling = TypeNameHandling.Auto,
    };
    return JsonConvert.DeserializeObject<Bloatware[]>(json, settings).ToKeyedDictionary();
  }

  private IImmutableDictionary<string, Component> LoadComponents()
  {
    string json = Util.StringFromResource("Component.json");
    return JsonConvert.DeserializeObject<Component[]>(json).ToKeyedDictionary();
  }

  private IImmutableDictionary<string, ImageLanguage> LoadImageLanguages()
  {
    string json = Util.StringFromResource("ImageLanguage.json");
    return JsonConvert.DeserializeObject<ImageLanguage[]>(json).ToKeyedDictionary();
  }

  private IImmutableDictionary<string, KeyboardIdentifier> LoadKeyboardIdentifiers()
  {
    string json = Util.StringFromResource("KeyboardIdentifier.json");
    return JsonConvert.DeserializeObject<KeyboardIdentifier[]>(json).ToKeyedDictionary();
  }

  private IImmutableDictionary<string, GeoLocation> LoadGeoLocations()
  {
    string json = Util.StringFromResource("GeoId.json");
    return JsonConvert.DeserializeObject<GeoLocation[]>(json).ToKeyedDictionary();
  }

  private IImmutableDictionary<string, UserLocale> LoadUserLocales()
  {
    string json = Util.StringFromResource("UserLocale.json");
    JsonConverter[] converters = [new KeyboardConverter(this), new GeoLocationConverter(this)];
    return JsonConvert.DeserializeObject<UserLocale[]>(json, converters).ToKeyedDictionary();
  }

  private IImmutableDictionary<string, WindowsEdition> LoadWindowsEditions()
  {
    string json = Util.StringFromResource("WindowsEdition.json");
    return JsonConvert.DeserializeObject<WindowsEdition[]>(json).ToKeyedDictionary();
  }

  private IImmutableDictionary<string, TimeOffset> LoadTimeOffsets()
  {
    string json = Util.StringFromResource("TimeOffset.json");
    return JsonConvert.DeserializeObject<TimeOffset[]>(json).ToKeyedDictionary();
  }

  private IImmutableDictionary<string, DesktopIcon> LoadDesktopIcons()
  {
    string json = Util.StringFromResource("DesktopIcon.json");
    return JsonConvert.DeserializeObject<DesktopIcon[]>(json).ToKeyedDictionary();
  }

  private IImmutableDictionary<string, StartFolder> LoadStartFolders()
  {
    string json = Util.StringFromResource("StartFolder.json");
    JsonConverter[] converters = [new Base64Converter()];
    return JsonConvert.DeserializeObject<StartFolder[]>(json, converters).ToKeyedDictionary();
  }

  private void VerifyData()
  {
    VerifyUniqueKeys(Components.Values, e => e.Id);

    VerifyUniqueKeys(WindowsEditions.Values, e => e.Id);
    VerifyUniqueKeys(WindowsEditions.Values, e => e.DisplayName);
    VerifyUniqueKeys(WindowsEditions.Values, e => e.ProductKey);

    VerifyUniqueKeys(UserLocales.Values, e => e.Id);
    VerifyUniqueKeys(UserLocales.Values, e => e.DisplayName);

    VerifyUniqueKeys(KeyboardIdentifiers.Values, e => e.Id);
    VerifyUniqueKeys(KeyboardIdentifiers.Values, e => e.DisplayName);

    VerifyUniqueKeys(ImageLanguages.Values, e => e.Id);
    VerifyUniqueKeys(ImageLanguages.Values, e => e.DisplayName);

    VerifyUniqueKeys(TimeOffsets.Values, e => e.Id);
    VerifyUniqueKeys(TimeOffsets.Values, e => e.DisplayName);

    VerifyUniqueKeys(DesktopIcons.Values, e => e.Id);
    VerifyUniqueKeys(DesktopIcons.Values, e => e.Guid);
    VerifyUniqueKeys(DesktopIcons.Values, e => e.DisplayName);

    VerifyUniqueKeys(StartFolders.Values, e => e.Id);
    VerifyUniqueKeys(StartFolders.Values, e => e.DisplayName);
    VerifyUniqueKeys(StartFolders.Values, e => Convert.ToBase64String(e.Bytes));
  }

  private static void VerifyUniqueKeys<T>(IEnumerable<T> items, Func<T, object> keySelector)
  {
    items.GroupBy(keySelector).ToList().ForEach(group =>
    {
      if (group.Count() != 1)
      {
        throw new ArgumentException($"'{group.Key}' occurs more than once.");
      }
    });
  }

  public ExplicitTimeZoneSettings CreateExplicitTimeZoneSettings(string id)
  {
    return new ExplicitTimeZoneSettings(
      TimeZone: Lookup<TimeOffset>(id)
    );
  }

  public IImmutableDictionary<string, DesktopIcon> DesktopIcons { get; }

  public IImmutableDictionary<string, StartFolder> StartFolders { get; }

  public IImmutableDictionary<string, TimeOffset> TimeOffsets { get; }

  public IImmutableDictionary<string, GeoLocation> GeoLocations { get; }

  public IImmutableDictionary<string, Component> Components { get; }

  public IImmutableDictionary<string, Bloatware> Bloatwares { get; }

  public IImmutableDictionary<string, KeyboardIdentifier> KeyboardIdentifiers { get; }

  public IImmutableDictionary<string, UserLocale> UserLocales { get; }

  public IImmutableDictionary<string, ImageLanguage> ImageLanguages { get; }

  public IImmutableDictionary<string, WindowsEdition> WindowsEditions { get; }

  [return: NotNull]
  private static T Lookup<T>(IImmutableDictionary<string, T> dic, string key) where T : IKeyed
  {
    if (dic.TryGetValue(key, out T? value))
    {
      return value;
    }
    else
    {
      throw new ConfigurationException($"Could not find an element of type '{nameof(T)}' with key '{key}'.");
    }
  }

  [return: NotNull]
  public T Lookup<T>(string key) where T : class, IKeyed
  {
    return (T)(object)(this as object switch
    {
      _ when typeof(T) == typeof(WindowsEdition) => Lookup(WindowsEditions, key),
      _ when typeof(T) == typeof(UserLocale) => Lookup(UserLocales, key),
      _ when typeof(T) == typeof(ImageLanguage) => Lookup(ImageLanguages, key),
      _ when typeof(T) == typeof(KeyboardIdentifier) => Lookup(KeyboardIdentifiers, key),
      _ when typeof(T) == typeof(TimeOffset) => Lookup(TimeOffsets, key),
      _ when typeof(T) == typeof(Bloatware) => Lookup(Bloatwares, key),
      _ when typeof(T) == typeof(GeoLocation) => Lookup(GeoLocations, key),
      _ when typeof(T) == typeof(DesktopIcon) => Lookup(DesktopIcons, key),
      _ when typeof(T) == typeof(Component) => Lookup(Components, key),
      _ => throw new NotSupportedException(),
    });
  }

  public XmlDocument GenerateXml(Configuration config)
  {
    var doc = Util.XmlDocumentFromResource("autounattend.xml");
    var ns = new XmlNamespaceManager(doc.NameTable);
    ns.AddNamespace("u", "urn:schemas-microsoft-com:unattend");
    ns.AddNamespace("wcm", "http://schemas.microsoft.com/WMIConfig/2002/State");
    ns.AddNamespace("s", Constants.MyNamespaceUri);

    ModifierContext context = new(
      Configuration: config,
      Document: doc,
      NamespaceManager: ns,
      Generator: this,
      SpecializeScript: new SpecializeSequence(),
      FirstLogonScript: new FirstLogonSequence(),
      UserOnceScript: new UserOnceSequence(),
      DefaultUserScript: new DefaultUserSequence()
    );

    new List<Modifier> {
      new AccessibilityModifier(context),
      new ComputerNameModifier(context),
      new BypassModifier(context),
      new ProductKeyModifier(context),
      new LocalesModifier(context),
      new DiskModifier(context),
      new UsersModifier(context),
      new BloatwareModifier(context),
      new ExpressSettingsModifier(context),
      new WifiModifier(context),
      new EmptyElementsModifier(context),
      new LockoutModifier(context),
      new PasswordExpirationModifier(context),
      new OptimizationsModifier(context),
      new PersonalizationModifier(context),
      new TimeZoneModifier(context),
      new WdacModifier(context),
      new WingetModifier(context),
      new ScriptModifier(context),
      new SpecializeModifier(context),
      new UserOnceModifier(context),
      new DefaultUserModifier(context),
      new DeleteModifier(context),
      new FirstLogonModifier(context),
      new ComponentsModifier(context),
      new OrderModifier(context),
      new ProcessorArchitectureModifier(context),
      new PrettyModifier(context),
    }.ForEach(modifier =>
    {
      modifier.Process();
    });

    Util.ValidateAgainstSchema(doc, "autounattend.xsd");

    return doc;
  }

  /// <summary>
  /// Serializes an <c>autounattend.xml</c> document such that it can be reliably processed. Windows Setup expects 
  /// the document to have an <c>encoding="utf-8"</c> encoding declaration, but actually only supports ASCII characters.
  /// </summary>
  public static byte[] Serialize(XmlDocument doc)
  {
    using var mstr = new MemoryStream();
    {
      using StreamWriter sw = new(mstr, encoding: Encoding.ASCII, leaveOpen: true);
      sw.Write(@"<?xml version=""1.0"" encoding=""utf-8""?>" + "\r\n");
      sw.Close();
    }
    {
      using var writer = XmlWriter.Create(mstr, new XmlWriterSettings()
      {
        Encoding = Encoding.ASCII,
        OmitXmlDeclaration = true,
        CloseOutput = true,
        Indent = true,
        IndentChars = "\t",
        NewLineChars = "\r\n",
      });
      doc.Save(writer);
      writer.Close();
    }
    return mstr.ToArray();
  }
}

public record class ModifierContext(
  XmlDocument Document,
  XmlNamespaceManager NamespaceManager,
  Configuration Configuration,
  UnattendGenerator Generator,
  SpecializeSequence SpecializeScript,
  FirstLogonSequence FirstLogonScript,
  UserOnceSequence UserOnceScript,
  DefaultUserSequence DefaultUserScript
);

abstract class Modifier(ModifierContext context)
{
  public XmlDocument Document { get; } = context.Document;

  public XmlNamespaceManager NamespaceManager { get; } = context.NamespaceManager;

  public Configuration Configuration { get; } = context.Configuration;

  public UnattendGenerator Generator { get; } = context.Generator;

  public CommandBuilder CommandBuilder { get; } = new CommandBuilder(hidePowerShellWindows: context.Configuration.System.HidePowerShellWindows);

  public SpecializeSequence SpecializeScript { get; } = context.SpecializeScript;

  public FirstLogonSequence FirstLogonScript { get; } = context.FirstLogonScript;

  public UserOnceSequence UserOnceScript { get; } = context.UserOnceScript;

  public DefaultUserSequence DefaultUserScript { get; } = context.DefaultUserScript;

  public XmlElement NewSimpleElement(string name, XmlElement parent, string innerText)
  {
    return Util.NewSimpleElement(name, parent, innerText, Document, NamespaceManager);
  }

  public XmlElement NewElement(string name, XmlElement parent)
  {
    return Util.NewElement(name, parent, Document, NamespaceManager);
  }

  public abstract void Process();

  public CommandAppender GetAppender(CommandConfig config)
  {
    return new CommandAppender(Document, NamespaceManager, config);
  }

  public void AddXmlFile(XmlDocument xml, string path)
  {
    string ToPrettyString()
    {
      using var sw = new StringWriter();
      using var writer = XmlWriter.Create(sw, new XmlWriterSettings()
      {
        CloseOutput = true,
        OmitXmlDeclaration = true,
        Indent = true,
        IndentChars = "\t",
        NewLineChars = "\r\n",
      });
      xml.Save(writer);
      writer.Close();
      return sw.ToString();
    }

    AddFile(ToPrettyString(), path);
  }

  public string AddXmlFile(string xml, string name)
  {
    string path = $@"C:\Windows\Setup\Scripts\{name}";
    var doc = new XmlDocument();
    doc.LoadXml(xml);
    AddXmlFile(doc, path);
    return path;
  }

  public string AddXmlFile(string resourceName)
  {
    string path = $@"C:\Windows\Setup\Scripts\{resourceName}";
    AddXmlFile(Util.XmlDocumentFromResource(resourceName), path);
    return path;
  }

  public string AddTextFile(string name, string content, Action<StringWriter>? before = null, Action<StringWriter>? after = null)
  {
    string destination = $@"C:\Windows\Setup\Scripts\{name}";
    StringWriter writer = new();
    before?.Invoke(writer);
    writer.WriteLine(content);
    after?.Invoke(writer);
    AddFile(writer.ToString(), destination);
    return destination;
  }

  public string AddTextFile(string resourceName, Action<StringWriter>? before = null, Action<StringWriter>? after = null)
  {
    return AddTextFile(resourceName, content: Util.StringFromResource(resourceName), before: before, after: after);
  }

  private void AddFile(string content, string path)
  {
    {
      XmlNode root = Document.SelectSingleNodeOrThrow("/u:unattend", NamespaceManager);
      XmlNode? extensions = root.SelectSingleNode("s:Extensions", NamespaceManager);
      if (extensions == null)
      {
        extensions = Document.CreateElement("Extensions", Constants.MyNamespaceUri);
        root.AppendChild(extensions);

        XmlNode extractScript = Document.CreateElement("ExtractScript", Constants.MyNamespaceUri);
        extensions.AppendChild(extractScript);
        extractScript.AppendChild(
          Document.CreateTextNode(
            Util.Indent(
              Util.StringFromResource("ExtractScripts.ps1")
            )
          )
        );

        CommandAppender appender = GetAppender(CommandConfig.Specialize);
        appender.Append(
          CommandBuilder.PowerShellCommand(@"$xml = [xml]::new(); $xml.Load('C:\Windows\Panther\unattend.xml'); $sb = [scriptblock]::Create( $xml.unattend.Extensions.ExtractScript ); Invoke-Command -ScriptBlock $sb -ArgumentList $xml;")
        );
      }

      XmlElement file = Document.CreateElement("File", Constants.MyNamespaceUri);
      file.SetAttribute("path", path);
      extensions.AppendChild(file);
      file.AppendChild(Document.CreateTextNode(Util.Indent(content)));
    }
  }
}
