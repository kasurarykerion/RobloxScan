import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import os
from PIL import Image, ImageTk
import time
import threading
from pathlib import Path
from tkinter import font
import sys
import re
from typing import Dict, List, Tuple

# Application version
__version__ = "1.0.0"

# Fix appearance mode and theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PulsingButton(ctk.CTkButton):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pulsing = False
        self._pulse_color = kwargs.get("hover_color", "#1f6aa5")
        self._normal_color = kwargs.get("fg_color", "#2B2B2B")
        
    def start_pulse(self):
        self._pulsing = True
        self._pulse()
        
    def stop_pulse(self):
        self._pulsing = False
        self.configure(fg_color=self._normal_color)
        
    def _pulse(self):
        if not self._pulsing:
            return
        
        current_color = self.cget("fg_color")
        new_color = self._pulse_color if current_color == self._normal_color else self._normal_color
        self.configure(fg_color=new_color)
        self.after(1000, self._pulse)

class FloatingFrame(ctk.CTkFrame):
    def __init__(self, *args, **kwargs):
        # Ensure we have proper background color
        if "fg_color" not in kwargs:
            kwargs["fg_color"] = "#2B2B2B"
        super().__init__(*args, **kwargs)
        self._float_offset = 0
        self._floating = False
        
    def start_floating(self):
        self._floating = True
        self._float()
        
    def stop_floating(self):
        self._floating = False
        
    def _float(self):
        if not self._floating:
            return
            
        self._float_offset = (self._float_offset + 1) % 20
        offset = abs(10 - self._float_offset) / 5  # Reduced floating effect
        self.pack_configure(pady=(20 + offset, 20 - offset))
        self.after(100, self._float)

def load_montserrat_font():
    # Get the current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    fonts_dir = os.path.join(current_dir, "fonts")
    
    # Create fonts directory if it doesn't exist
    os.makedirs(fonts_dir, exist_ok=True)
    
    # Define font paths
    font_regular = os.path.join(fonts_dir, "Montserrat-Regular.ttf")
    font_bold = os.path.join(fonts_dir, "Montserrat-Bold.ttf")
    
    # Load fonts if they exist, otherwise download them
    if not (os.path.exists(font_regular) and os.path.exists(font_bold)):
        try:
            import requests
            
            # URLs for Montserrat fonts
            urls = {
                font_regular: "https://github.com/google/fonts/raw/main/ofl/montserrat/static/Montserrat-Regular.ttf",
                font_bold: "https://github.com/google/fonts/raw/main/ofl/montserrat/static/Montserrat-Bold.ttf"
            }
            
            for font_path, url in urls.items():
                if not os.path.exists(font_path):
                    response = requests.get(url)
                    with open(font_path, 'wb') as f:
                        f.write(response.content)
            
        except Exception as e:
            print(f"Error loading Montserrat font: {e}")
            return False
    
    # Load fonts into tkinter
    for font_path in [font_regular, font_bold]:
        if os.path.exists(font_path):
            try:
                tk.font.families()
                tk.font.Font(font=font_path)
            except Exception as e:
                print(f"Error loading font {font_path}: {e}")
                return False
    
    return True

class AnimatedLabel(ctk.CTkLabel):
    def __init__(self, *args, **kwargs):
        # Ensure we have proper text color
        if "text_color" not in kwargs:
            kwargs["text_color"] = "white"
        super().__init__(*args, **kwargs)
        self._animation_thread = None
        self._stop_animation = False
        self._rainbow_colors = ["#FF5555", "#FF8C55", "#FFDD55", "#55FF55", "#55AAFF", "#8055FF", "#FF55DD"]
        self._current_color_index = 0

    def start_rainbow(self):
        self._animate_rainbow()

    def _animate_rainbow(self):
        self._current_color_index = (self._current_color_index + 1) % len(self._rainbow_colors)
        self.configure(text_color=self._rainbow_colors[self._current_color_index])
        self.after(150, self._animate_rainbow)

    def animate_text(self, text, delay=0.05):
        if self._animation_thread and self._animation_thread.is_alive():
            self._stop_animation = True
            self._animation_thread.join()
        
        self._stop_animation = False
        self._animation_thread = threading.Thread(target=self._animate_text_thread, args=(text, delay))
        self._animation_thread.start()

    def _animate_text_thread(self, text, delay):
        current_text = ""
        for char in text:
            if self._stop_animation:
                return
            current_text += char
            self.after(0, self.configure, {"text": current_text})
            time.sleep(delay)

class VulnerabilityExplainer:
    EXPLANATIONS = {
        "RemoteEvent Abuse": {
            "description": "RemoteEvents can be exploited to perform unauthorized actions on the server.",
            "fix": """1. Always validate player permissions before processing RemoteEvent requests
2. Implement rate limiting for RemoteEvents
3. Use filtered events when possible
4. Example fix:

local function handleRemoteEvent(player, ...)
    -- Validate player
    if not isAuthorized(player) then return end
    -- Rate limiting
    if isRateLimited(player) then return end
    -- Process event
    processEvent(...)
end"""
        },
        "Global Variable Usage": {
            "description": "Global variables can be modified by any script, potentially leading to security breaches.",
            "fix": """1. Use local variables instead of globals
2. Implement proper data encapsulation
3. Use module scripts for shared data
4. Example fix:

-- Instead of _G.PlayerData = {}
local PlayerData = {}
local function getPlayerData(player)
    return PlayerData[player.UserId]
end"""
        },
        "Potential Backdoor (getfenv)": {
            "description": "getfenv() can be used to modify the environment and inject malicious code.",
            "fix": """1. Avoid using getfenv
2. Use proper scoping and modules
3. Implement secure environment handling
4. Example fix:

-- Instead of modifying environment
local function secureFunction()
    local localEnv = {}
    -- Set up secure environment
    return function()
        -- Use localEnv safely
    end
end"""
        },
        "Potential Backdoor (loadstring)": {
            "description": "loadstring can execute arbitrary code and is a common vector for exploits.",
            "fix": """1. Never use loadstring with user input
2. Use proper configuration systems
3. Implement secure code loading
4. Example fix:

-- Instead of loadstring(userInput)()
local validCommands = {
    jump = function() end,
    sit = function() end
}
local function executeCommand(cmdName)
    local cmd = validCommands[cmdName]
    if cmd then cmd() end
end"""
        },
        "Unsecured HTTP Request": {
            "description": "Unsecured HTTP requests can lead to data leaks and injection attacks.",
            "fix": """1. Always use HTTPS
2. Validate URLs before requests
3. Implement proper error handling
4. Example fix:

local function secureHttpGet(url)
    if not url:match("^https://") then
        return nil, "HTTPS required"
    end
    local success, result = pcall(function()
        return HttpService:GetAsync(url, true)
    end)
    return success and result or nil
end"""
        }
    }

class RobloxScan(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Load Montserrat font
        self.has_montserrat = load_montserrat_font()
        self.title_font = ("Montserrat", 28, "bold") if self.has_montserrat else ("Helvetica", 28, "bold")
        self.normal_font = ("Montserrat", 13) if self.has_montserrat else ("Helvetica", 13)
        self.bold_font = ("Montserrat", 14, "bold") if self.has_montserrat else ("Helvetica", 14, "bold")
        self.code_font = ("Consolas", 12)

        # Configure window
        self.title(f"RobloxScan v{__version__}")
        self.geometry("1000x800")
        self.minsize(800, 600)
        
        # Set theme for this instance
        self.configure(fg_color="#1A1A1A")

        # Create main container with padding
        self.main_frame = FloatingFrame(self, fg_color="#2B2B2B", corner_radius=10)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.main_frame.start_floating()

        # Animated title
        self.title_label = AnimatedLabel(
            self.main_frame,
            text="",
            font=self.title_font,
            text_color="white"
        )
        self.title_label.pack(pady=20)
        self.title_label.animate_text("🚀 RobloxScan 🔍")
        self.title_label.start_rainbow()

        # File selection frame
        self.file_frame = ctk.CTkFrame(self.main_frame, fg_color="#333333", corner_radius=8)
        self.file_frame.pack(fill="x", padx=20, pady=10)

        self.file_path = ctk.CTkEntry(
            self.file_frame,
            placeholder_text="Select Lua script to scan...",
            width=600,
            font=self.normal_font,
            fg_color="#222222",
            text_color="white",
            placeholder_text_color="#888888"
        )
        self.file_path.pack(side="left", padx=(10, 10), pady=10)

        self.browse_btn = PulsingButton(
            self.file_frame,
            text="Browse",
            command=self.browse_file,
            width=100,
            font=self.normal_font,
            fg_color="#2B5480",
            hover_color="#1f6aa5",
            text_color="white"
        )
        self.browse_btn.pack(side="left", padx=(0, 10), pady=10)

        # Progress bar
        self.progress_frame = ctk.CTkFrame(self.main_frame, fg_color="#333333", corner_radius=8)
        self.progress_frame.pack(fill="x", padx=20, pady=10)
        
        self.progress_label = AnimatedLabel(
            self.progress_frame,
            text="Progress: 0%",
            font=self.normal_font,
            text_color="white"
        )
        self.progress_label.pack(pady=(10, 5))

        self.progress = ctk.CTkProgressBar(
            self.progress_frame,
            fg_color="#222222",
            progress_color="#1f6aa5",
            height=15
        )
        self.progress.pack(fill="x", padx=10, pady=(0, 10))
        self.progress.set(0)

        # Results area
        self.results_frame = ctk.CTkFrame(self.main_frame, fg_color="#333333", corner_radius=8)
        self.results_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.results_label = AnimatedLabel(
            self.results_frame,
            text="Scan Results",
            font=self.bold_font,
            text_color="white"
        )
        self.results_label.pack(pady=10)

        # Split view for results and explanation
        self.split_frame = ctk.CTkFrame(self.results_frame, fg_color="#333333")
        self.split_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Results text area
        self.results_text = ctk.CTkTextbox(
            self.split_frame,
            wrap="word",
            font=self.code_font,
            fg_color="#222222",
            text_color="#DDDDDD",
            corner_radius=5
        )
        self.results_text.pack(side="left", fill="both", expand=True, padx=(0, 5), pady=10)

        # Explanation text area
        self.explanation_text = ctk.CTkTextbox(
            self.split_frame,
            wrap="word",
            font=self.normal_font,
            fg_color="#222222",
            text_color="#DDDDDD",
            corner_radius=5
        )
        self.explanation_text.pack(side="right", fill="both", expand=True, padx=(5, 0), pady=10)
        self.explanation_text.insert("1.0", "Select a vulnerability to see explanation and fix...")

        # Bottom buttons frame
        self.button_frame = ctk.CTkFrame(self.main_frame, fg_color="#333333", corner_radius=8)
        self.button_frame.pack(fill="x", padx=20, pady=10)

        self.scan_btn = PulsingButton(
            self.button_frame,
            text="Start Scan",
            command=self.start_scan,
            width=150,
            font=self.normal_font,
            fg_color="#2d8a2d",
            hover_color="#1f6f1f",
            text_color="white"
        )
        self.scan_btn.pack(side="left", padx=10, pady=10)

        self.explain_btn = PulsingButton(
            self.button_frame,
            text="Explain & Fix",
            command=self.explain_vulnerability,
            width=150,
            font=self.normal_font,
            fg_color="#8a2d2d",
            hover_color="#6f1f1f",
            text_color="white",
            state="disabled"
        )
        self.explain_btn.pack(side="left", padx=10, pady=10)

        self.save_btn = PulsingButton(
            self.button_frame,
            text="Save Report",
            command=self.save_report,
            width=150,
            state="disabled",
            font=self.normal_font,
            fg_color="#2d8a8a",
            hover_color="#1f6f6f",
            text_color="white"
        )
        self.save_btn.pack(side="left", padx=10, pady=10)

        self.clear_btn = PulsingButton(
            self.button_frame,
            text="Clear",
            command=self.clear_results,
            width=150,
            font=self.normal_font,
            fg_color="#8a8a2d",
            hover_color="#6f6f1f",
            text_color="white"
        )
        self.clear_btn.pack(side="right", padx=10, pady=10)

        # Add about button
        self.about_btn = PulsingButton(
            self.button_frame,
            text="About",
            command=self.show_about,
            width=100,
            font=self.normal_font,
            fg_color="#555555",
            hover_color="#777777",
            text_color="white"
        )
        self.about_btn.pack(side="right", padx=10, pady=10)

        # Store current vulnerabilities
        self.current_vulnerabilities = []
        
        # Bind text selection event
        self.results_text.bind("<<Selection>>", self.on_text_select)
        
        # Create directory for reports if it doesn't exist
        os.makedirs("reports", exist_ok=True)

    def show_about(self):
        about_window = ctk.CTkToplevel(self)
        about_window.title("About RobloxScan")
        about_window.geometry("500x400")
        about_window.resizable(False, False)
        about_window.configure(fg_color="#1A1A1A")
        
        # Make the window modal
        about_window.transient(self)
        about_window.grab_set()
        
        # Add content
        frame = ctk.CTkFrame(about_window, fg_color="#2B2B2B", corner_radius=10)
        frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        title = ctk.CTkLabel(
            frame, 
            text="RobloxScan", 
            font=self.title_font,
            text_color="#55AAFF"
        )
        title.pack(pady=(20, 5))
        
        version = ctk.CTkLabel(
            frame, 
            text=f"Version {__version__}",
            font=self.normal_font,
            text_color="white"
        )
        version.pack(pady=(0, 20))
        
        description = ctk.CTkLabel(
            frame,
            text="A security scanner for Roblox Lua scripts.\nDetects common vulnerabilities and provides fix recommendations.",
            font=self.normal_font,
            text_color="white",
            wraplength=400
        )
        description.pack(pady=10)
        
        features = ctk.CTkLabel(
            frame,
            text="Features:\n• RemoteEvent abuse detection\n• Global variable exposure detection\n• Backdoor detection\n• Unsecured HTTP request detection\n• Detailed fix recommendations",
            font=self.normal_font,
            text_color="white",
            justify="left"
        )
        features.pack(pady=20)
        
        credits = ctk.CTkLabel(
            frame,
            text="© 2023 RobloxScan Team\nMade with ❤️ for the Roblox community",
            font=self.normal_font,
            text_color="#AAAAAA"
        )
        credits.pack(pady=20)
        
        close_btn = ctk.CTkButton(
            frame,
            text="Close",
            command=about_window.destroy,
            width=100,
            font=self.normal_font,
            fg_color="#2B5480",
            hover_color="#1f6aa5"
        )
        close_btn.pack(pady=10)

    def on_text_select(self, event):
        try:
            selection = self.results_text.selection_get()
            if "Line" in selection and "Potential" in selection:
                self.explain_btn.configure(state="normal")
                self.explain_btn.start_pulse()
            else:
                self.explain_btn.configure(state="disabled")
                self.explain_btn.stop_pulse()
        except:
            self.explain_btn.configure(state="disabled")
            self.explain_btn.stop_pulse()

    def explain_vulnerability(self):
        try:
            selection = self.results_text.selection_get()
            for vuln_type in VulnerabilityExplainer.EXPLANATIONS:
                if vuln_type in selection:
                    explanation = VulnerabilityExplainer.EXPLANATIONS[vuln_type]
                    self.explanation_text.delete("1.0", "end")
                    
                    # Insert vulnerability type with warning emoji
                    self.explanation_text.insert("1.0", f"⚠️ {vuln_type}\n\n", "title")
                    
                    # Insert description
                    self.explanation_text.insert("end", "Description:\n", "heading")
                    self.explanation_text.insert("end", f"{explanation['description']}\n\n", "normal")
                    
                    # Insert fix information
                    self.explanation_text.insert("end", "How to Fix:\n", "heading")
                    
                    # Split the fix text to separate code from instructions
                    fix_parts = explanation['fix'].split("\n4. Example fix:\n\n")
                    
                    if len(fix_parts) == 2:
                        # Insert the instructions
                        self.explanation_text.insert("end", fix_parts[0] + "\n4. Example fix:\n\n", "normal")
                        
                        # Insert the code with special tag
                        self.explanation_text.insert("end", fix_parts[1], "code")
                    else:
                        # Fallback if the format is different
                        self.explanation_text.insert("end", explanation['fix'], "normal")
                    
                    # Configure text tags
                    self.explanation_text.tag_configure("title", font=self.bold_font)
                    self.explanation_text.tag_configure("heading", font=self.bold_font)
                    self.explanation_text.tag_configure("normal", font=self.normal_font)
                    self.explanation_text.tag_configure("code", font=self.code_font, background="#1A1A1A", foreground="#55AAFF")
                    
                    return
        except Exception as e:
            print(f"Error explaining vulnerability: {e}")
            pass

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Lua files", "*.lua"), ("All files", "*.*")]
        )
        if file_path:
            self.file_path.delete(0, "end")
            self.file_path.insert(0, file_path)
            self.browse_btn.start_pulse()

    def animate_progress(self, total_lines):
        for i in range(101):
            time.sleep(0.02)
            self.progress.set(i / 100)
            self.progress_label.configure(text=f"Progress: {i}%")
            self.update_idletasks()

    def start_scan(self):
        file_path = self.file_path.get()
        if not file_path or not os.path.exists(file_path):
            self.show_error("Please select a valid Lua file!")
            return

        self.results_text.delete("1.0", "end")
        self.explanation_text.delete("1.0", "end")
        self.explanation_text.insert("1.0", "Scanning...")
        self.save_btn.configure(state="disabled")
        self.explain_btn.configure(state="disabled")
        self.scan_btn.start_pulse()
        
        # Start scanning in a separate thread
        threading.Thread(target=self.scan_file, args=(file_path,), daemon=True).start()

    def scan_file(self, file_path):
        vulnerabilities = {
            r"FireServer\s*\([^)]*\)": "RemoteEvent Abuse",
            r"_G\.": "Global Variable Usage",
            r"getfenv\s*\(": "Potential Backdoor (getfenv)",
            r"loadstring\s*\(": "Potential Backdoor (loadstring)",
            r"HttpService": "Unsecured HTTP Request"
        }

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.readlines()

            # Start progress animation
            threading.Thread(target=self.animate_progress, args=(len(content),), daemon=True).start()

            results = []
            for line_num, line in enumerate(content, 1):
                for pattern, vuln_type in vulnerabilities.items():
                    if re.search(pattern, line):
                        results.append(f"⚠️ Line {line_num}: Potential {vuln_type}\n   {line.strip()}\n")

            # Animate results
            for result in results:
                self.results_text.insert("end", result + "\n")
                self.results_text.see("end")
                self.update_idletasks()
                time.sleep(0.1)

            if not results:
                self.results_text.insert("end", "✅ No vulnerabilities detected!\n")
                self.explanation_text.delete("1.0", "end")
                self.explanation_text.insert("1.0", "No vulnerabilities found in the code! 🎉")
            else:
                self.explanation_text.delete("1.0", "end")
                self.explanation_text.insert("1.0", "Select a vulnerability to see explanation and fix...")
                self.save_btn.configure(state="normal")
                self.save_btn.start_pulse()

        except Exception as e:
            self.show_error(f"Error scanning file: {str(e)}")
        finally:
            self.scan_btn.stop_pulse()

    def save_report(self):
        # Generate default filename based on current date and time
        default_filename = f"RobloxScan_Report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        default_path = os.path.join("reports", default_filename)
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir="reports",
            initialfile=default_filename
        )
        
        if file_path:
            with open(file_path, 'w') as f:
                f.write("ROBLOXSCAN SECURITY REPORT\n")
                f.write("=" * 30 + "\n\n")
                f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"File scanned: {self.file_path.get()}\n\n")
                f.write("Scan Results:\n")
                f.write("-" * 15 + "\n")
                f.write(self.results_text.get("1.0", "end"))
                if self.explanation_text.get("1.0", "end").strip():
                    f.write("\nDetailed Explanation:\n")
                    f.write("-" * 20 + "\n")
                    f.write(self.explanation_text.get("1.0", "end"))
                f.write("\n\nGenerated by RobloxScan v" + __version__)

    def clear_results(self):
        self.file_path.delete(0, "end")
        self.results_text.delete("1.0", "end")
        self.explanation_text.delete("1.0", "end")
        self.explanation_text.insert("1.0", "Select a vulnerability to see explanation and fix...")
        self.progress.set(0)
        self.progress_label.configure(text="Progress: 0%")
        self.save_btn.configure(state="disabled")
        self.explain_btn.configure(state="disabled")
        self.save_btn.stop_pulse()
        self.explain_btn.stop_pulse()
        self.scan_btn.stop_pulse()
        self.browse_btn.stop_pulse()

    def show_error(self, message):
        self.results_text.delete("1.0", "end")
        self.results_text.insert("end", f"❌ Error: {message}\n")
        self.explanation_text.delete("1.0", "end")
        self.explanation_text.insert("1.0", "An error occurred during scanning.")
        self.scan_btn.stop_pulse()

if __name__ == "__main__":
    app = RobloxScan()
    app.mainloop() 