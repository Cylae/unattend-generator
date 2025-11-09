using System;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using System.Xml;

namespace Schneegans.Unattend
{
    /// <summary>
    /// The main form of the Unattend Generator application.
    /// </summary>
    public partial class MainForm : Form
    {
        private TextBox wingetPackageTextBox;
        private Button addButton;
        private Button removeButton;
        private Button generateButton;
        private ListBox packagesListBox;
        private PropertyGrid propertyGrid;

        /// <summary>
        /// Initializes a new instance of the <see cref="MainForm"/> class.
        /// </summary>
        public MainForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            this.wingetPackageTextBox = new TextBox();
            this.addButton = new Button();
            this.removeButton = new Button();
            this.generateButton = new Button();
            this.packagesListBox = new ListBox();
            this.SuspendLayout();

            // wingetPackageTextBox
            this.wingetPackageTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.wingetPackageTextBox.Location = new System.Drawing.Point(6, 151);
            this.wingetPackageTextBox.Name = "wingetPackageTextBox";
            this.wingetPackageTextBox.Size = new System.Drawing.Size(242, 20);

            // addButton
            this.addButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.addButton.Location = new System.Drawing.Point(254, 149);
            this.addButton.Name = "addButton";
            this.addButton.Size = new System.Drawing.Size(75, 23);
            this.addButton.Text = "Add";
            this.addButton.UseVisualStyleBackColor = true;
            this.addButton.Click += new System.EventHandler(this.AddButton_Click);

            // removeButton
            this.removeButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.removeButton.Location = new System.Drawing.Point(254, 35);
            this.removeButton.Name = "removeButton";
            this.removeButton.Size = new System.Drawing.Size(75, 23);
            this.removeButton.Text = "Remove";
            this.removeButton.UseVisualStyleBackColor = true;
            this.removeButton.Click += new System.EventHandler(this.RemoveButton_Click);

            // generateButton
            this.generateButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.generateButton.Location = new System.Drawing.Point(12, 226);
            this.generateButton.Name = "generateButton";
            this.generateButton.Size = new System.Drawing.Size(340, 23);
            this.generateButton.Text = "Generate autounattend.xml file...";
            this.generateButton.UseVisualStyleBackColor = true;
            this.generateButton.Click += new System.EventHandler(this.GenerateButton_Click);

            // packagesListBox
            this.packagesListBox.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
            | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.packagesListBox.FormattingEnabled = true;
            this.packagesListBox.Location = new System.Drawing.Point(6, 6);
            this.packagesListBox.Name = "packagesListBox";
            this.packagesListBox.Size = new System.Drawing.Size(242, 134);

            // TabControl
            TabControl tabControl = new TabControl();
            tabControl.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
            | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            tabControl.Location = new System.Drawing.Point(12, 12);
            tabControl.Name = "tabControl";
            tabControl.SelectedIndex = 0;
            tabControl.Size = new System.Drawing.Size(340, 208);

            // Winget Tab
            TabPage wingetTabPage = new TabPage("Winget");
            wingetTabPage.Controls.Add(this.packagesListBox);
            wingetTabPage.Controls.Add(this.wingetPackageTextBox);
            wingetTabPage.Controls.Add(this.removeButton);
            wingetTabPage.Controls.Add(this.addButton);
            wingetTabPage.Location = new System.Drawing.Point(4, 22);
            wingetTabPage.Name = "wingetTabPage";
            wingetTabPage.Padding = new System.Windows.Forms.Padding(3);
            wingetTabPage.Size = new System.Drawing.Size(332, 182);
            wingetTabPage.TabIndex = 0;
            wingetTabPage.Text = "Winget";
            wingetTabPage.UseVisualStyleBackColor = true;

            // Settings Tab
            TabPage settingsTabPage = new TabPage("Settings");
            this.propertyGrid = new PropertyGrid();
            this.propertyGrid.Dock = DockStyle.Fill;
            this.propertyGrid.Location = new System.Drawing.Point(0, 0);
            this.propertyGrid.Name = "propertyGrid";
            this.propertyGrid.Size = new System.Drawing.Size(332, 182);
            this.propertyGrid.TabIndex = 0;
            this.propertyGrid.SelectedObject = Configuration.Default;
            settingsTabPage.Controls.Add(this.propertyGrid);
            settingsTabPage.Location = new System.Drawing.Point(4, 22);
            settingsTabPage.Name = "settingsTabPage";
            settingsTabPage.Size = new System.Drawing.Size(332, 182);
            settingsTabPage.TabIndex = 1;
            settingsTabPage.Text = "Settings";
            settingsTabPage.UseVisualStyleBackColor = true;

            tabControl.TabPages.Add(wingetTabPage);
            tabControl.TabPages.Add(settingsTabPage);

            // MainForm
            this.ClientSize = new System.Drawing.Size(364, 261);
            this.Controls.Add(this.generateButton);
            this.Controls.Add(tabControl);
            this.Name = "MainForm";
            this.Text = "Unattend Generator";
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        private void AddButton_Click(object sender, EventArgs e)
        {
            string packageName = wingetPackageTextBox.Text.Trim();
            if (string.IsNullOrEmpty(packageName))
            {
                MessageBox.Show("Please enter a Winget package name.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (packageName.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0)
            {
                MessageBox.Show("The package name contains invalid characters.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (packagesListBox.Items.Contains(packageName))
            {
                MessageBox.Show("This package is already in the list.", "Information", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (WingetPackageExists(packageName))
            {
                packagesListBox.Items.Add(packageName);
                wingetPackageTextBox.Clear();
            }
            else
            {
                MessageBox.Show($"The Winget package '{packageName}' was not found.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RemoveButton_Click(object sender, EventArgs e)
        {
            if (packagesListBox.SelectedItem != null)
            {
                packagesListBox.Items.Remove(packagesListBox.SelectedItem);
            }
            else
            {
                MessageBox.Show("Please select a package to remove.", "Information", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void GenerateButton_Click(object sender, EventArgs e)
        {
            using (SaveFileDialog saveFileDialog = new SaveFileDialog())
            {
                saveFileDialog.Filter = "XML files (*.xml)|*.xml";
                saveFileDialog.FileName = "autounattend.xml";
                saveFileDialog.Title = "Save the autounattend.xml file";

                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    GenerateAutounattendXml(saveFileDialog.FileName);
                }
            }
        }

        private bool WingetPackageExists(string packageName)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "winget",
                    Arguments = $"search \"{packageName}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    return output.Contains(packageName, StringComparison.OrdinalIgnoreCase);
                }
            }
            catch (Exception)
            {
                MessageBox.Show("Winget is not installed or not in the PATH.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        private void GenerateAutounattendXml(string filePath)
        {
            UnattendGenerator generator = new UnattendGenerator();
            var packages = packagesListBox.Items.Cast<string>().ToImmutableList();

            Configuration config = (Configuration)propertyGrid.SelectedObject;
            config = config with
            {
                Winget = new WingetSettings(Packages: packages)
            };

            XmlDocument xml = generator.GenerateXml(config);
            File.WriteAllBytes(filePath, UnattendGenerator.Serialize(xml));
            MessageBox.Show($"The autounattend.xml file has been successfully generated at:\n{filePath}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
