namespace DarkSkies.Gui;

internal sealed class MainForm : Form
{
    private readonly TextBox assemblyPath = CreatePathBox();
    private readonly TextBox metadataPath = CreatePathBox();
    private readonly TextBox outputPath = CreatePathBox();
    private readonly Button startButton = new() { Text = "Analyze", Height = 42, Dock = DockStyle.Fill };
    private readonly ProgressBar progress = new() { Style = ProgressBarStyle.Marquee, Visible = false, Dock = DockStyle.Fill };
    private readonly TextBox status = new()
    {
        Multiline = true,
        ReadOnly = true,
        ScrollBars = ScrollBars.Vertical,
        Dock = DockStyle.Fill,
        BackColor = Color.FromArgb(24, 27, 33),
        ForeColor = Color.Gainsboro
    };

    public MainForm()
    {
        Text = "DarkSkies";
        Width = 820;
        Height = 560;
        MinimumSize = new Size(700, 480);
        BackColor = Color.FromArgb(31, 35, 43);
        ForeColor = Color.Gainsboro;
        AllowDrop = true;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(18),
            ColumnCount = 3,
            RowCount = 7
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 155));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 14));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));

        AddPathRow(layout, 0, "GameAssembly.dll", assemblyPath, BrowseAssembly);
        AddPathRow(layout, 1, "global-metadata.dat", metadataPath, BrowseMetadata);
        AddPathRow(layout, 2, "Output folder", outputPath, BrowseOutput);
        layout.Controls.Add(startButton, 1, 3);
        layout.Controls.Add(progress, 2, 3);
        layout.Controls.Add(status, 0, 5);
        layout.SetColumnSpan(status, 3);
        layout.Controls.Add(new Label { Text = "Files can also be dragged onto this window.", AutoSize = true, ForeColor = Color.DarkGray }, 0, 6);
        layout.SetColumnSpan(layout.GetControlFromPosition(0, 6)!, 3);
        Controls.Add(layout);

        startButton.Click += async (_, _) => await AnalyzeAsync();
        DragEnter += OnDragEnter;
        DragDrop += OnDragDrop;
    }

    private async Task AnalyzeAsync()
    {
        if (!File.Exists(assemblyPath.Text) || !File.Exists(metadataPath.Text) || string.IsNullOrWhiteSpace(outputPath.Text))
        {
            MessageBox.Show(this, "Select GameAssembly.dll, global-metadata.dat, and an output folder.", Text,
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        var output = Path.GetFullPath(outputPath.Text);
        Directory.CreateDirectory(output);
        var report = Path.Combine(output, "analysis-report.json");
        var exports = Path.Combine(output, "il2cpp-exports.json");
        var normalized = Path.Combine(output, "normalized-metadata.dat");
        startButton.Enabled = false;
        progress.Visible = true;
        status.Text = "Scanning native functions and metadata...";
        try
        {
            var exitCode = await Task.Run(() => DarkSkiesApplication.RunAsync([
                assemblyPath.Text,
                metadataPath.Text,
                "--out", report,
                "--exports-out", exports,
                "--normalized-out", normalized
            ]));
            status.Text = $"Finished with status {exitCode}.\r\n\r\nReport: {report}\r\nExports: {exports}\r\n" +
                          (File.Exists(normalized) ? $"Normalized metadata: {normalized}" : "Normalized metadata was not emitted because its standard header did not validate.");
        }
        catch (Exception exception)
        {
            status.Text = exception.ToString();
        }
        finally
        {
            progress.Visible = false;
            startButton.Enabled = true;
        }
    }

    private static TextBox CreatePathBox() => new()
    {
        Dock = DockStyle.Fill,
        AllowDrop = true,
        BackColor = Color.FromArgb(24, 27, 33),
        ForeColor = Color.Gainsboro,
        BorderStyle = BorderStyle.FixedSingle
    };

    private static void AddPathRow(TableLayoutPanel layout, int row, string label, TextBox box, EventHandler browse)
    {
        layout.Controls.Add(new Label { Text = label, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, row);
        layout.Controls.Add(box, 1, row);
        var button = new Button { Text = "Browse", Dock = DockStyle.Fill };
        button.Click += browse;
        layout.Controls.Add(button, 2, row);
    }

    private void BrowseAssembly(object? sender, EventArgs args) => BrowseFile(assemblyPath, "GameAssembly.dll|GameAssembly.dll|DLL files|*.dll|All files|*.*");
    private void BrowseMetadata(object? sender, EventArgs args) => BrowseFile(metadataPath, "Metadata|*.dat|All files|*.*");

    private void BrowseOutput(object? sender, EventArgs args)
    {
        using var dialog = new FolderBrowserDialog { ShowNewFolderButton = true };
        if (dialog.ShowDialog(this) == DialogResult.OK)
            outputPath.Text = dialog.SelectedPath;
    }

    private void BrowseFile(TextBox target, string filter)
    {
        using var dialog = new OpenFileDialog { Filter = filter, CheckFileExists = true };
        if (dialog.ShowDialog(this) == DialogResult.OK)
            target.Text = dialog.FileName;
    }

    private void OnDragEnter(object? sender, DragEventArgs args)
    {
        args.Effect = args.Data?.GetDataPresent(DataFormats.FileDrop) == true ? DragDropEffects.Copy : DragDropEffects.None;
    }

    private void OnDragDrop(object? sender, DragEventArgs args)
    {
        if (args.Data?.GetData(DataFormats.FileDrop) is not string[] files)
            return;
        foreach (var file in files)
        {
            if (Path.GetFileName(file).Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase))
                assemblyPath.Text = file;
            else if (Path.GetFileName(file).Equals("global-metadata.dat", StringComparison.OrdinalIgnoreCase))
                metadataPath.Text = file;
            else if (Directory.Exists(file))
                outputPath.Text = file;
        }
    }
}
