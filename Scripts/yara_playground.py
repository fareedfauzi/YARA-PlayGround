import sys
import subprocess
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
import yara
import os
import re
import hashlib
import time
from pathlib import Path
import threading
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
import json
import requests
import zipfile
import shutil
import shlex
from urllib.parse import urlparse

# --- Dark Theme ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

CLR_BG = "#0B0E14"
CLR_CARD = "#151921"
CLR_ACCENT = "#5865F2"
CLR_SUCCESS = "#2ECC71"
CLR_ERROR = "#F04747"
CLR_TEXT_DIM = "#8E9297"

class CTKTooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        
        # Bind to the main widget
        self.widget.bind("<Enter>", self.show_tooltip, add="+")
        self.widget.bind("<Leave>", self.hide_tooltip, add="+")
        
        # CTA widgets (like buttons) have internal components (canvas, label).
        # We bind to them recursively to ensure the entire area triggers the tooltip.
        self._bind_recursive(self.widget)

    def _bind_recursive(self, w):
        for child in w.winfo_children():
            child.bind("<Enter>", self.show_tooltip, add="+")
            child.bind("<Leave>", self.hide_tooltip, add="+")
            self._bind_recursive(child)

    def show_tooltip(self, event=None):
        if self.tooltip_window or not self.text:
            return
            
        # Offset positioning: Below the widget, centered horizontally
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(tw, text=self.text, justify='left',
                         background="#2B2B2B", foreground="#FFFFFF", 
                         relief='flat', borderwidth=0,
                         padx=8, pady=6,
                         font=("Inter", 10),
                         wraplength=300) # Wrap long descriptions
        label.pack()
        
        # Accent border logic
        tw.configure(background="#5865F2")

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

class YaraPlaygroundApp(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self):
        super().__init__()
        self.TkdndVersion = TkinterDnD._require(self)
        
        # Window Configuration
        self.title("YARA Playground")
        self.geometry("1400x900")
        self.configure(fg_color=CLR_BG)
        
        # State
        self.master_rules = None
        self.is_scanning = False
        self.abort_collection = False
        self.sidebar_collapsed = False
        self.analysis_rules_path = ctk.StringVar(value="Select YARA rules directory...")
        self.lab_rule_path = ctk.StringVar(value="Browse rule file or just paste your rules in the editor")
        self.lab_view_mode = "split"
        
        # Generator State
        self.yargen_path = ctk.StringVar(value="Not Configured (Setup Required)")
        self.gen_sample_path = ctk.StringVar(value="Select folder containing samples...")
        self.gen_custom_flags = ctk.StringVar(value="--score")
        self.is_generating = False
        self.search_index = []
        self.search_path = ctk.StringVar(value="Default (./Master Rules)")
        
        # UI Structure
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.setup_sidebar()
        self.setup_main_area()
        self.load_app_settings()

    def load_app_settings(self):
        try:
            base_dir = Path(__file__).parent.parent if not getattr(sys, 'frozen', False) else Path(sys.executable).parent
            cfg_path = base_dir / "config" / "app_settings.json"
            if cfg_path.exists():
                settings = json.loads(cfg_path.read_text())
                if "yargen_path" in settings:
                    self.yargen_path.set(settings["yargen_path"])
        except:
            pass

    def save_app_settings(self):
        try:
            base_dir = Path(__file__).parent.parent if not getattr(sys, 'frozen', False) else Path(sys.executable).parent
            cfg_dir = base_dir / "config"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            cfg_path = cfg_dir / "app_settings.json"
            settings = {"yargen_path": self.yargen_path.get()}
            cfg_path.write_text(json.dumps(settings, indent=4))
        except:
            pass

    def pick_analysis_rules(self):
        d = filedialog.askdirectory()
        if d: self.analysis_rules_path.set(d)

    def reset_analysis(self):
        self.target_path.set("Select threat sample...")
        self.analysis_rules_path.set("Select YARA rules directory...")
        self.log_to_textbox(self.analysis_out, "", clear=True)
        self.clear_hits_gallery()
        self.view_editor.configure(state="normal")
        self.view_editor.delete("1.0", "end")
        self.view_editor.configure(state="disabled")
        
        # Restore placeholder
        if hasattr(self, "rule_placeholder"):
            try: self.rule_placeholder.destroy()
            except: pass
        self.rule_placeholder = ctk.CTkLabel(self.view_editor.master, text="Select a threat badge to analyze rule logic",
                                            font=("Inter", 12, "italic"), text_color=CLR_TEXT_DIM)
        self.rule_placeholder.place(relx=0.5, rely=0.5, anchor="center")
        self.update_status("Scanner Reset", "ok")

    def clear_hits_gallery(self):
        # Safely clear only intended widgets
        for widget in self.hits_gallery.winfo_children():
            if widget.winfo_name().startswith('!ctk'): # Only destroy CTk components we added
                widget.destroy()
            
        # Center placeholder using relative placement
        self.hits_placeholder = ctk.CTkLabel(self.hits_gallery, text="No Detections Found", 
                                            font=("Inter", 13, "italic"), text_color=CLR_TEXT_DIM)
        self.hits_placeholder.place(relx=0.5, rely=0.5, anchor="center")
        self.after(100, self.toggle_gallery_scrollbar)

    def toggle_gallery_scrollbar(self):
        try:
            # CTK ScrollableFrame internal bits
            canvas = self.hits_gallery._parent_canvas
            scrollbar = self.hits_gallery._scrollbar
            
            # If content height is less than canvas height, hide it
            if canvas.bbox("all")[3] <= canvas.winfo_height():
                scrollbar.grid_remove()
            else:
                scrollbar.grid()
        except: pass

    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=CLR_CARD)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(8, weight=1)
        
        # Premium Emoji Support for Windows rendering
        self.emoji_font = ("Segoe UI Emoji", 12)
        self.emoji_font_bold = ("Segoe UI Emoji", 11, "bold")
        
        # Toggle Button using directional arrow
        self.btn_toggle = ctk.CTkButton(self.sidebar, text="⬅️", width=35, height=35, 
                                        font=self.emoji_font,
                                        fg_color="transparent", hover_color="#202225",
                                        command=self.toggle_sidebar)
        self.btn_toggle.grid(row=0, column=0, sticky="nw", padx=15, pady=15)

        self.logo_label = ctk.CTkLabel(self.sidebar, text="YARA PLAYGROUND", font=("Inter", 18, "bold"), text_color=CLR_TEXT_DIM)
        self.logo_label.grid(row=1, column=0, padx=20, pady=(10, 5))
        
        self.tagline = ctk.CTkLabel(self.sidebar, text="Everything you need for YARA!", font=("Inter", 11), text_color=CLR_ACCENT)
        self.tagline.grid(row=2, column=0, padx=20, pady=(0, 30))
        
        self.btn_analysis = ctk.CTkButton(self.sidebar, text="  YARA Scanner", 
                                          image=None, anchor="w", font=self.emoji_font,
                                          fg_color="transparent", text_color="white",
                                          hover_color="#202225", command=lambda: self.select_tab("analysis"))
        self.btn_analysis.grid(row=3, column=0, padx=15, pady=10, sticky="ew")
        
        self.btn_lab = ctk.CTkButton(self.sidebar, text="  YARA Editor", 
                                     image=None, anchor="w", font=self.emoji_font,
                                     fg_color="transparent", text_color="white",
                                     hover_color="#202225", command=lambda: self.select_tab("lab"))
        self.btn_lab.grid(row=4, column=0, padx=15, pady=10, sticky="ew")

        self.btn_collector = ctk.CTkButton(self.sidebar, text="  YARA Collector", 
                                          image=None, anchor="w", font=self.emoji_font,
                                          fg_color="transparent", text_color="white",
                                          hover_color="#202225", command=lambda: self.select_tab("collector"))
        self.btn_collector.grid(row=5, column=0, padx=15, pady=10, sticky="ew")

        self.btn_generator = ctk.CTkButton(self.sidebar, text="  YARA Generator", 
                                          image=None, anchor="w", font=self.emoji_font,
                                          fg_color="transparent", text_color="white",
                                          hover_color="#202225", command=lambda: self.select_tab("generator"))
        self.btn_generator.grid(row=6, column=0, padx=15, pady=10, sticky="ew")

        self.btn_search = ctk.CTkButton(self.sidebar, text="  YARA Search", 
                                       image=None, anchor="w", font=self.emoji_font,
                                       fg_color="transparent", text_color="white",
                                       hover_color="#202225", command=lambda: self.select_tab("search"))
        self.btn_search.grid(row=7, column=0, padx=15, pady=10, sticky="ew")

        # Status footer in sidebar
        self.status_label = ctk.CTkLabel(self.sidebar, text="Status: All good!", font=("Inter", 11), text_color=CLR_SUCCESS)
        self.status_label.grid(row=9, column=0, pady=20)

    def toggle_sidebar(self):
        if not self.sidebar_collapsed:
            # Symmetrical Collapse
            self.sidebar.configure(width=60)
            self.btn_toggle.configure(text="➡️")
            self.btn_toggle.grid(padx=10, sticky="n") # Perfectly centered
            self.logo_label.grid_remove()
            self.tagline.grid_remove()
            self.btn_analysis.configure(text="🔬", width=40, anchor="center")
            self.btn_analysis.grid(padx=10, sticky="n")
            self.btn_lab.configure(text="📝", width=40, anchor="center")
            self.btn_lab.grid(padx=10, sticky="n")
            self.btn_collector.configure(text="📡", width=40, anchor="center") # Radar is more balanced than satellite
            self.btn_collector.grid(padx=10, sticky="n")
            self.btn_generator.configure(text="⚡", width=40, anchor="center")
            self.btn_generator.grid(padx=10, sticky="n")
            self.btn_search.configure(text="🔎", width=40, anchor="center")
            self.btn_search.grid(padx=10, sticky="n")
            self.status_label.grid_remove()
            self.sidebar_collapsed = True
        else:
            # Full Expansion
            self.sidebar.configure(width=240)
            self.btn_toggle.configure(text="⬅️")
            self.btn_toggle.grid(padx=15, sticky="nw")
            self.logo_label.grid()
            self.tagline.grid()
            self.btn_analysis.configure(text="  YARA Scanner", width=190, anchor="w")
            self.btn_analysis.grid(padx=15, sticky="ew")
            self.btn_lab.configure(text="  YARA Editor", width=190, anchor="w")
            self.btn_lab.grid(padx=15, sticky="ew")
            self.btn_collector.configure(text="  YARA Collector", width=190, anchor="w")
            self.btn_collector.grid(padx=15, sticky="ew")
            self.btn_generator.configure(text="  YARA Generator", width=190, anchor="w")
            self.btn_generator.grid(padx=15, sticky="ew")
            self.btn_search.configure(text="  YARA Search", width=190, anchor="w")
            self.btn_search.grid(padx=15, sticky="ew")
            self.status_label.grid()
            self.sidebar_collapsed = False

    def setup_styles(self):
        # Configure standard ttk styles for the Treeview (Tables)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", 
                        background=CLR_CARD, 
                        foreground="white", 
                        fieldbackground=CLR_CARD, 
                        borderwidth=0, 
                        font=("Inter", 9), 
                        rowheight=28)
        style.configure("Treeview.Heading", 
                        background=CLR_BG, 
                        foreground=CLR_ACCENT, 
                        borderwidth=0, 
                        font=("Inter Bold", 9))
        style.map("Treeview", 
                  background=[("selected", CLR_ACCENT)], 
                  foreground=[("selected", "white")])

    def create_table(self, parent, columns):
        container = ctk.CTkFrame(parent, fg_color="transparent")
        container.pack(expand=True, fill="both", padx=5, pady=5)
        
        # Wrapping standard Treeview in CTK
        tree = ttk.Treeview(container, columns=columns, show="headings", selectmode="browse")
        
        vsb = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        for col in columns:
            tree.heading(col, text=col.upper())
            # Use specific widths for different column types
            if col == "#":
                w = 40
            elif "Path" in col:
                w = 600
            else:
                w = 180
            tree.column(col, width=w, minwidth=40, stretch=False, anchor="w")
        
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)
        
        # Right-click context menu
        tree.bind("<Button-3>", lambda e: self.show_context_menu(e, tree))
        return tree

    def auto_fit_columns(self, tree):
        import tkinter.font as tkfont
        f = tkfont.Font(family="Inter", size=9)
        for col in tree["columns"]:
            max_w = f.measure(col.upper()) + 20
            for item in tree.get_children():
                val = str(tree.set(item, col))
                w = f.measure(val) + 20
                if w > max_w: max_w = w
            # Cap width for extreme paths but allow reasonable growth
            tree.column(col, width=min(max_w, 800))

    def show_context_menu(self, event, tree):
        item = tree.identify_row(event.y)
        if not item: return
        tree.selection_set(item)
        
        menu = tk.Menu(self, tearoff=0, bg=CLR_CARD, fg="white", activebackground=CLR_ACCENT)
        cols = tree["columns"]
        vals = tree.item(item, "values")
        
        def copy_val(idx):
            self.clipboard_clear()
            self.clipboard_append(vals[idx])
            self.update_status(f"Copied {cols[idx]}", "ok")

        for i, col in enumerate(cols):
            menu.add_command(label=f"Copy {col}", command=lambda i=i: copy_val(i))
        
        menu.post(event.x_root, event.y_root)

    def setup_main_area(self):
        self.setup_styles() # Apply table styles
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=30, pady=30)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)
        
        self.views = {}
        self.create_analysis_view()
        self.create_lab_view()
        self.create_collector_view()
        self.create_generator_view()
        self.create_search_view()
        
        self.select_tab("analysis")

    def create_analysis_view(self):
        view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.views["analysis"] = view
        
        # 1. Integrated Header
        header = ctk.CTkFrame(view, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="File Analysis Mode", font=("Inter", 24, "bold")).pack()
        ctk.CTkLabel(header, text="YARA Rule Matching and Scanner", 
                     text_color=CLR_TEXT_DIM, font=("Inter", 12)).pack()
        
        # 2. Controls Area (Sleek Integrated Command Center)
        controls = ctk.CTkFrame(view, fg_color=CLR_CARD, corner_radius=15, border_width=1, border_color="#1E232E")
        controls.pack(fill="x", pady=(0, 20))
        
        inner_ctrl = ctk.CTkFrame(controls, fg_color="transparent")
        inner_ctrl.pack(fill="x", padx=30, pady=20)
        inner_ctrl.grid_columnconfigure(1, weight=1)
        
        # Path Selectors with Iconography
        ctk.CTkLabel(inner_ctrl, text="TARGET SAMPLE(S):", font=self.emoji_font_bold, text_color=CLR_ACCENT).grid(row=0, column=0, padx=(0, 15), sticky="w")
        self.target_path = ctk.StringVar(value="Waiting for sample...")
        ctk.CTkLabel(inner_ctrl, textvariable=self.target_path, fg_color=CLR_BG, corner_radius=10, height=35, anchor="w", padx=15).grid(row=0, column=1, sticky="ew", pady=5)
        
        target_btns = ctk.CTkFrame(inner_ctrl, fg_color="transparent")
        target_btns.grid(row=0, column=2, padx=(15, 0))
        ctk.CTkButton(target_btns, text="File", width=55, height=32, command=self.pick_file).pack(side="left", padx=(0, 5))
        ctk.CTkButton(target_btns, text="Folder", width=65, height=32, command=self.pick_target_folder).pack(side="left")
        
        ctk.CTkLabel(inner_ctrl, text="RULES FOLDER:", font=self.emoji_font_bold, text_color=CLR_ACCENT).grid(row=1, column=0, padx=(0, 15), sticky="w")
        self.analysis_rules_path = ctk.StringVar(value="Select your rule repository folder...")
        ctk.CTkLabel(inner_ctrl, textvariable=self.analysis_rules_path, fg_color=CLR_BG, corner_radius=10, height=35, anchor="w", padx=15).grid(row=1, column=1, sticky="ew")
        ctk.CTkButton(inner_ctrl, text="Browse", width=125, height=32, command=self.pick_analysis_rules).grid(row=1, column=2, padx=(15, 0))
        
        action_btns = ctk.CTkFrame(controls, fg_color="transparent")
        action_btns.pack(side="bottom", anchor="e", padx=30, pady=(0, 20))
        
        ctk.CTkButton(action_btns, text="Reset Analysis", fg_color="#2D1616", border_width=1, border_color="#4D1C1C", 
                      hover_color="#3D1C1C", command=self.reset_analysis, width=150, height=45, font=("Inter", 12, "bold")).pack(side="left", padx=(0, 15))
                      
        ctk.CTkButton(action_btns, text="Scan", fg_color=CLR_SUCCESS, hover_color="#00A156", 
                      command=self.run_file_scan, width=180, height=45, font=("Inter", 13, "bold")).pack(side="left")

        # 3. Optimized 3-Pane Dashboard (Tiered Layout)
        split = ctk.CTkFrame(view, fg_color="transparent")
        split.pack(fill="both", expand=True)
        split.grid_columnconfigure(0, weight=4) # Detected Rules (Gallery)
        split.grid_columnconfigure(1, weight=6) # Rule Content (Viewer)
        split.grid_rowconfigure(0, weight=6)    # Side-by-Side Area
        split.grid_rowconfigure(1, weight=4)    # Technical Console Area

        # TOP LEFT: Detected Rules Gallery
        hits_pane = ctk.CTkFrame(split, fg_color="transparent")
        hits_pane.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 10))
        hits_pane.grid_rowconfigure(1, weight=1)
        hits_pane.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(hits_pane, text="Detected Rules", font=("Inter", 11, "bold"), text_color=CLR_TEXT_DIM).grid(row=0, column=0, sticky="w", pady=(0, 5))

        self.hits_gallery = ctk.CTkScrollableFrame(hits_pane, fg_color=CLR_CARD, corner_radius=15,
                                                 border_width=1, border_color="#1E232E",
                                                 scrollbar_fg_color="transparent")
        self.hits_gallery.grid(row=1, column=0, sticky="nsew")
        
        # Auto-hide scrollbar logic
        self.hits_gallery._parent_canvas.bind("<Configure>", lambda e: self.toggle_gallery_scrollbar())
        self.hits_gallery._view_before_map = False # internal state track
        
        self.clear_hits_gallery()

        # TOP RIGHT: Rule Content Viewer
        view_pane = ctk.CTkFrame(split, fg_color="transparent")
        view_pane.grid(row=0, column=1, sticky="nsew", pady=(0, 10))
        view_pane.grid_rowconfigure(1, weight=1)
        view_pane.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(view_pane, text="RULE SOURCE", font=("Inter", 11, "bold"), text_color=CLR_TEXT_DIM).grid(row=0, column=0, sticky="w", pady=(0, 5))

        viewer_frame = ctk.CTkFrame(view_pane, fg_color=CLR_CARD, corner_radius=15, 
                                   border_width=1, border_color="#1E232E")
        viewer_frame.grid(row=1, column=0, sticky="nsew")
        
        self.view_editor = ctk.CTkTextbox(viewer_frame, fg_color="transparent", 
                                         font=("Cascadia Code", 13), border_width=0, state="disabled")
        self.view_editor.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.rule_placeholder = ctk.CTkLabel(viewer_frame, text="Select a detection badge to analyze source logic",
                                            font=("Inter", 12, "italic"), text_color=CLR_TEXT_DIM)
        self.rule_placeholder.place(relx=0.5, rely=0.5, anchor="center")

        # BOTTOM: Full-Width Output Console
        console_pane = ctk.CTkFrame(split, fg_color="transparent")
        console_pane.grid(row=1, column=0, columnspan=2, sticky="nsew")
        console_pane.grid_rowconfigure(1, weight=1)
        console_pane.grid_columnconfigure(0, weight=1)

        console_header = ctk.CTkFrame(console_pane, fg_color="transparent")
        console_header.grid(row=0, column=0, sticky="ew", pady=(0, 5))

        ctk.CTkLabel(console_header, text="OUTPUT CONSOLE", font=("Inter", 11, "bold"), text_color=CLR_TEXT_DIM).pack(side="left")
        self.analysis_loader = ctk.CTkLabel(console_header, text="", font=("Inter", 14, "bold"), text_color=CLR_ACCENT)
        self.analysis_loader.pack(side="left", padx=10)

        self.analysis_out = ctk.CTkTextbox(console_pane, fg_color=CLR_CARD, corner_radius=15, 
                                          border_width=1, border_color="#1E232E", 
                                          font=("Consolas", 12), state="disabled")
        self.analysis_out.grid(row=1, column=0, sticky="nsew")

    def create_lab_view(self):
        view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.views["lab"] = view
        
        # 1. Header
        header = ctk.CTkFrame(view, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="YARA Editor & Tester", font=("Inter", 24, "bold")).pack()
        ctk.CTkLabel(header, text="Edit YARA and test the YARA rule quality", 
                     text_color=CLR_TEXT_DIM, font=("Inter", 12)).pack()

        # 2. Control Console (Consolidated & Organized)
        controls = ctk.CTkFrame(view, fg_color=CLR_CARD, corner_radius=15, border_width=1, border_color="#1E232E")
        controls.pack(fill="x", pady=(0, 20))
        
        inner = ctk.CTkFrame(controls, fg_color="transparent")
        inner.pack(fill="x", padx=30, pady=20)
        inner.grid_columnconfigure(1, weight=1)

        # Row 1: Target Folder (Samples)
        self.lab_path = ctk.StringVar(value="Select target specific file sample or folder containing samples...")
        ctk.CTkLabel(inner, text="TARGET:", font=self.emoji_font_bold, text_color=CLR_ACCENT).grid(row=0, column=0, padx=(0, 15), sticky="w")
        ctk.CTkLabel(inner, textvariable=self.lab_path, fg_color=CLR_BG, corner_radius=10, height=35, anchor="w", padx=15).grid(row=0, column=1, sticky="ew", pady=5)
        
        target_btns = ctk.CTkFrame(inner, fg_color="transparent")
        target_btns.grid(row=0, column=2, padx=(15, 0), sticky="w")
        ctk.CTkButton(target_btns, text="Browse file", width=110, height=32, command=self.pick_lab_file).pack(side="left", padx=(0, 10))
        ctk.CTkButton(target_btns, text="Browse folder", width=110, height=32, command=self.pick_folder).pack(side="left")

        # Row 2: Rule File
        ctk.CTkLabel(inner, text="RULE FILE:", font=self.emoji_font_bold, text_color=CLR_ACCENT).grid(row=1, column=0, padx=(0, 15), sticky="w")
        ctk.CTkLabel(inner, textvariable=self.lab_rule_path, fg_color=CLR_BG, corner_radius=10, height=35, anchor="w", padx=15).grid(row=1, column=1, sticky="ew")
        
        rule_btns = ctk.CTkFrame(inner, fg_color="transparent")
        rule_btns.grid(row=1, column=2, padx=(15, 0), sticky="w")
        ctk.CTkButton(rule_btns, text="Browse Rule", width=110, height=32, command=self.pick_lab_rule_file).pack(side="left", padx=(0, 10))
        ctk.CTkButton(rule_btns, text="Save As", width=90, height=32, fg_color="#202225", border_width=1, border_color="#30363D",
                      command=lambda: self.save_lab_rule(True)).pack(side="left", padx=(0, 5))
        self.btn_save_lab = ctk.CTkButton(rule_btns, text="Save", width=80, height=32, fg_color=CLR_SUCCESS, hover_color="#27AE60",
                                        text_color="white", font=("Inter", 12, "bold"),
                                        command=lambda: self.save_lab_rule(False))
        self.btn_save_lab.pack(side="left")

        # Initial button state
        self.after(100, self.update_lab_buttons_state)
        
        # 3. Panes Header (Layout Switcher moved here)
        panes_ctrl = ctk.CTkFrame(view, fg_color="transparent")
        panes_ctrl.pack(fill="x", pady=(0, 10))
        
        mode_frame = ctk.CTkFrame(panes_ctrl, fg_color=CLR_BG, corner_radius=8, border_width=1, border_color="#30363D")
        mode_frame.pack(side="left")
        
        self.btn_layout_split = ctk.CTkButton(mode_frame, text="Split View", width=90, height=30, corner_radius=6,
                                            fg_color=CLR_ACCENT, hover_color="#4752C4",
                                            command=lambda: self.update_lab_layout("split"))
        self.btn_layout_split.pack(side="left", padx=2, pady=2)

        self.btn_layout_editor = ctk.CTkButton(mode_frame, text="Editor", width=80, height=30, corner_radius=6,
                                             fg_color="transparent", hover_color="#1E232E",
                                             command=lambda: self.update_lab_layout("editor"))
        self.btn_layout_editor.pack(side="left", padx=2, pady=2)

        self.btn_layout_results = ctk.CTkButton(mode_frame, text="Results", width=80, height=30, corner_radius=6,
                                              fg_color="transparent", hover_color="#1E232E",
                                              command=lambda: self.update_lab_layout("results"))
        self.btn_layout_results.pack(side="left", padx=2, pady=2)

        # Editor & Results Split
        paned = ctk.CTkFrame(view, fg_color="transparent")
        paned.pack(fill="both", expand=True)
        
        # Editor Left (With Line Numbering)
        self.lab_left_pane = ctk.CTkFrame(paned, fg_color=CLR_BG)
        self.lab_left_pane.place(relx=0, rely=0, relwidth=0.45, relheight=1.0)
        self.lab_left_pane.grid_columnconfigure(0, weight=1)
        self.lab_left_pane.grid_rowconfigure(1, weight=1)
        
        self.editor_header = ctk.CTkFrame(self.lab_left_pane, fg_color="transparent")
        self.editor_header.grid(row=0, column=0, sticky="ew", pady=(5, 0))
        ctk.CTkLabel(self.editor_header, text="YARA EDITOR", font=("Inter", 11, "bold"), text_color=CLR_TEXT_DIM).pack(side="left")
        
        # Editor Container (Gutter + Text)
        # Added top padding to match CTK Tabview tab bar offset for perfect visual alignment
        editor_container = ctk.CTkFrame(self.lab_left_pane, fg_color="#0D1117", border_width=1, border_color="#30363D", corner_radius=15)
        editor_container.grid(row=1, column=0, sticky="nsew", pady=(42, 0))
        
        self.line_numbers = tk.Canvas(editor_container, width=35, bg="#0D1117", highlightthickness=0, bd=0)
        self.line_numbers.pack(side="left", fill="y", padx=(10, 0), pady=15)
        
        self.lab_editor = ctk.CTkTextbox(editor_container, fg_color="transparent", 
                                        font=("Cascadia Code", 13), undo=True, border_width=0)
        self.lab_editor.pack(side="left", fill="both", expand=True, padx=5, pady=10)
        
        # Status Label below Editor
        self.lab_status = ctk.CTkLabel(self.lab_left_pane, text="Ready", font=("Inter", 11), 
                                      text_color=CLR_TEXT_DIM, wraplength=500, justify="left")
        self.lab_status.grid(row=2, column=0, sticky="w", pady=(5, 0))

        # Synchronize Gutter
        self.lab_editor._textbox.bind("<KeyRelease>", self.on_editor_change)
        self.lab_editor._textbox.bind("<Configure>", lambda e: self.redraw_line_numbers())
        self.lab_editor._textbox.bind("<MouseWheel>", lambda e: self.after(1, self.redraw_line_numbers))
        
        # Configure Highlighting Tags
        self.lab_editor.tag_config("kw", foreground=CLR_ACCENT)
        self.lab_editor.tag_config("str", foreground=CLR_SUCCESS)
        self.lab_editor.tag_config("com", foreground=CLR_TEXT_DIM)
        self.lab_editor.tag_config("var", foreground="#FF79C6")
        self.lab_editor.tag_config("hex", foreground="#BD93F9")
        self.lab_editor.tag_config("regex", foreground="#F4A261")
        self.lab_editor.tag_config("num", foreground="#E9C46A")
        
        # Enable Drag & Drop for Editor (Direct binding to internal widget for reliability)
        self.lab_editor._textbox.drop_target_register(DND_FILES)
        self.lab_editor._textbox.dnd_bind('<<Drop>>', self.handle_editor_drop)

        # Load Template
        template = 'rule Rule_01 {\n    meta:\n        author = "Rule Lab"\n\n    strings:\n        $s1 = "malicious_payload"\n        $s2 = { E2 34 ?? 56 78 }\n\n    condition:\n        any of them\n}'
        self.lab_editor.insert("end", template)
        self.apply_highlighting()
        
        # Results Right (Tabs)
        self.lab_right_pane = ctk.CTkFrame(paned, fg_color=CLR_BG)
        self.lab_right_pane.place(relx=0.47, rely=0, relwidth=0.53, relheight=1.0)
        self.lab_right_pane.grid_columnconfigure(0, weight=1)
        self.lab_right_pane.grid_rowconfigure(1, weight=1)
        
        self.results_header = ctk.CTkFrame(self.lab_right_pane, fg_color="transparent")
        self.results_header.grid(row=0, column=0, sticky="ew", pady=(5, 0))
        ctk.CTkLabel(self.results_header, text="DETECTION SUMMARY", font=("Inter", 11, "bold"), text_color=CLR_TEXT_DIM).pack(side="left")

        self.res_view = ctk.CTkTabview(self.lab_right_pane, fg_color=CLR_CARD, corner_radius=15)
        self.res_view.grid(row=1, column=0, sticky="nsew")
        
        # Dummy footer to match left pane height balance
        self.res_footer_spacer = ctk.CTkLabel(self.lab_right_pane, text=" ", font=("Inter", 11))
        self.res_footer_spacer.grid(row=2, column=0, pady=(5, 0))
        self.res_view.add("Detections")
        self.res_view.add("Undetected")
        self.res_view.add("Summary")
        
        self.hit_tree = self.create_table(self.res_view.tab("Detections"), ("#", "Filename", "Rules", "MD5", "Full Path"))
        self.clean_tree = self.create_table(self.res_view.tab("Undetected"), ("#", "Filename", "MD5", "Full Path"))
        
        self.summary_box = ctk.CTkTextbox(self.res_view.tab("Summary"), fg_color="transparent", 
                                         font=("Consolas", 12), state="disabled")
        self.summary_box.pack(fill="both", expand=True)
        
        # Lab Action Bar
        lab_actions = ctk.CTkFrame(view, fg_color="transparent")
        lab_actions.pack(side="bottom", fill="x", pady=(10, 0))
        
        ctk.CTkButton(lab_actions, text="Check Syntax", fg_color="#202225", command=self.lab_check_syntax).pack(side="left", padx=10)
        ctk.CTkButton(lab_actions, text="✨ Fix Rule (AI)", fg_color="#1A3F2B", hover_color="#27AE60", 
                      command=self.fix_rule_ai).pack(side="left", padx=(0, 10))
        ctk.CTkButton(lab_actions, text="Execute YARA Scan", fg_color=CLR_ACCENT, command=self.run_batch_scan).pack(side="left")
        
        # Utility buttons
        ctk.CTkButton(lab_actions, text="Clear Results", fg_color="#F04747", hover_color="#D83C3C", 
                      width=120, command=self.clear_lab_results).pack(side="right", padx=10)
        ctk.CTkButton(lab_actions, text="Copy All MD5s", fg_color="#202225", 
                      width=120, command=self.copy_all_md5s).pack(side="right")

    def create_collector_view(self):
        view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.views["collector"] = view
        
        # 1. Header
        header = ctk.CTkFrame(view, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="YARA Rule Collector Dashboard", font=("Inter", 24, "bold")).pack()
        ctk.CTkLabel(header, text="Automated Rule Collecting • Rule Collection Engine", 
                     text_color=CLR_TEXT_DIM, font=("Inter", 12)).pack()

        # 2. Control Card
        controls = ctk.CTkFrame(view, fg_color=CLR_CARD, corner_radius=15, border_width=1, border_color="#1E232E")
        controls.pack(fill="x", pady=(0, 20))
        
        # Command Grid
        cmd_grid = ctk.CTkFrame(controls, fg_color="transparent")
        cmd_grid.pack(fill="x", padx=30, pady=(20, 10))
        
        # Action Buttons (Primary Grid)
        actions = [
            ("Collect or Update Rules", "#202225", lambda: self.start_collection("update"), "Sync and download new YARA rules from all configured GitHub repositories and public sources."),
            ("Validate Master Rules", "#202225", lambda: self.start_collection("validate"), "Scan the 'Master Rules' directory to find and isolate any malformed rules that cause compilation errors."),
            ("Fix Problematic Rules", "#202225", lambda: self.start_collection("fix"), "Apply automated regex-based repairs to fix common syntax errors in quarantined rules."),
            ("Fix Problematic Rules (AI)", "#1A3F2B", lambda: self.start_collection("ai_repair"), "Use LLM/AI logic to intelligently repair complex syntax errors and promote fixed rules back to the Master repository."),
            ("Deduplicate Rules", "#202225", lambda: self.start_collection("deduplicate"), "Scan the rulebase to find and remove exact duplicate rules to optimize scanner performance."),
            ("Reset Everything", "#2D1616", lambda: self.start_collection("reset"), "Wipe all downloaded, fixed, and problematic rules to start with a completely fresh environment.")
        ]
        
        self.collector_action_btns = []
        for i, (text, color, cmd, tip) in enumerate(actions):
            btn = ctk.CTkButton(cmd_grid, text=text, fg_color=color, anchor="center",
                                command=cmd, width=170, height=40, font=("Inter", 12, "bold"))
            btn.grid(row=0, column=i, padx=(0, 10), pady=10)
            self.collector_action_btns.append(btn)
            CTKTooltip(btn, tip)

        # Task Control (Stop + Status + Loader)
        control_bar = ctk.CTkFrame(controls, fg_color="#1A1F29", corner_radius=10)
        control_bar.pack(fill="x", padx=30, pady=(10, 20))
        
        self.btn_stop = ctk.CTkButton(control_bar, text="Stop Process", fg_color="#da372c", hover_color="#a92e25",
                                     command=self.stop_collection, width=150, height=45, font=("Inter", 12, "bold"), state="disabled")
        self.btn_stop.pack(side="left", padx=15, pady=12)
        CTKTooltip(self.btn_stop, "Gracefully abort the currently running collection or repair task.")
        
        status_info = ctk.CTkFrame(control_bar, fg_color="transparent")
        status_info.pack(side="left", fill="x", expand=True, padx=10)
        
        status_top = ctk.CTkFrame(status_info, fg_color="transparent")
        status_top.pack(fill="x")
        
        self.collector_status = ctk.StringVar(value="System Ready")
        ctk.CTkLabel(status_top, textvariable=self.collector_status, font=("Inter", 12, "bold"), text_color=CLR_ACCENT).pack(side="left")
        
        self.col_loader = ctk.CTkLabel(status_top, text="", font=("Inter", 14, "bold"), text_color=CLR_ACCENT, width=20)
        self.col_loader.pack(side="left", padx=5)
        
        self.col_progress = ctk.CTkProgressBar(status_info, fg_color=CLR_BG, progress_color=CLR_SUCCESS, height=10)
        self.col_progress.pack(fill="x", pady=(5, 0))
        self.col_progress.set(0)

        # Loader animation state
        self.loader_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.loader_idx = 0

        # 3. Log Console
        dash = ctk.CTkFrame(view, fg_color="transparent")
        dash.pack(fill="both", expand=True)
        
        # Log Header + Clear Button
        log_header = ctk.CTkFrame(dash, fg_color="transparent")
        log_header.pack(fill="x", pady=(0, 5))
        ctk.CTkLabel(log_header, text="Logs", font=("Inter", 11, "bold"), text_color=CLR_TEXT_DIM).pack(side="left")
        self.btn_clear_col_log = ctk.CTkButton(log_header, text="Clear Log", fg_color="#202225", height=24, width=80, font=("Inter", 10, "bold"),
                      command=lambda: (self.col_out.configure(state="normal"), self.col_out.delete("1.0", "end"), self.col_out.configure(state="disabled")))
        self.btn_clear_col_log.pack(side="right")
        CTKTooltip(self.btn_clear_col_log, "Clear the current session logs from the console window.")

        self.col_out = ctk.CTkTextbox(dash, fg_color=CLR_CARD, corner_radius=15, border_width=1, border_color="#1E232E", 
                                     font=("Consolas", 12), text_color="#A9B7C6")
        self.col_out.pack(fill="both", expand=True)
        self.log_to_textbox(self.col_out, "[*] System ready. Select a command to start collection...\n")

    def animate_collector_loader(self):
        if not self.is_scanning:
            self.col_loader.configure(text="")
            return
        
        self.col_loader.configure(text=self.loader_frames[self.loader_idx % len(self.loader_frames)])
        self.loader_idx += 1
        self.after(80, self.animate_collector_loader)

    def animate_analysis_loader(self):
        if not self.is_scanning:
            self.analysis_loader.configure(text="")
            return
        
        self.analysis_loader.configure(text=self.loader_frames[self.loader_idx % len(self.loader_frames)])
        self.loader_idx += 1
        self.after(80, self.animate_analysis_loader)

    def log_col(self, msg, type="info"):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = "[*]"
        if type == "success": prefix = "[+]"
        elif type == "error": prefix = "[!]"
        elif type == "warn": prefix = "[-]"
        
        full_msg = f"[{ts}] {prefix} {msg}\n"
        self.log_to_textbox(self.col_out, full_msg)

    def create_generator_view(self):
        view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.views["generator"] = view
        
        # 1. Header
        header = ctk.CTkFrame(view, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="YARA Auto-Generator", font=("Inter", 24, "bold")).pack()
        ctk.CTkLabel(header, text="Automated Rule Generation powered by yarGen-Go", 
                     text_color=CLR_TEXT_DIM, font=("Inter", 12)).pack()

        # 2. Command Console (Controls)
        controls = ctk.CTkFrame(view, fg_color=CLR_CARD, corner_radius=15, border_width=1, border_color="#1E232E")
        controls.pack(fill="x", pady=(0, 20))
        
        inner = ctk.CTkFrame(controls, fg_color="transparent")
        inner.pack(fill="x", padx=30, pady=20)
        inner.grid_columnconfigure(1, weight=1)

        # Tool Path Selection
        ctk.CTkLabel(inner, text="YARGEN TOOL:", font=self.emoji_font_bold, text_color=CLR_ACCENT).grid(row=0, column=0, padx=(0, 15), sticky="w")
        ctk.CTkLabel(inner, textvariable=self.yargen_path, fg_color=CLR_BG, corner_radius=10, height=35, anchor="w", padx=15).grid(row=0, column=1, sticky="ew", pady=5)
        ctk.CTkButton(inner, text="Browse yarGen binary", width=125, height=35, command=self.pick_yargen_path).grid(row=0, column=2, padx=(15, 0))

        # Sample Folder Selection
        ctk.CTkLabel(inner, text="SAMPLE FOLDER:", font=self.emoji_font_bold, text_color=CLR_ACCENT).grid(row=1, column=0, padx=(0, 15), sticky="w")
        ctk.CTkLabel(inner, textvariable=self.gen_sample_path, fg_color=CLR_BG, corner_radius=10, height=35, anchor="w", padx=15).grid(row=1, column=1, sticky="ew")
        ctk.CTkButton(inner, text="Browse Samples", width=125, height=35, command=self.pick_gen_sample).grid(row=1, column=2, padx=(15, 0))

        # Custom Flags Selection
        ctk.CTkLabel(inner, text="CUSTOM FLAGS:", font=self.emoji_font_bold, text_color=CLR_ACCENT).grid(row=2, column=0, padx=(0, 15), sticky="w")
        self.gen_flags_entry = ctk.CTkEntry(inner, textvariable=self.gen_custom_flags, placeholder_text="e.g. --super-rules --no-p-ext", height=35, fg_color=CLR_BG, border_color="#30363D")
        self.gen_flags_entry.grid(row=2, column=1, sticky="ew", pady=(5, 0))

        # Action Area
        action_frame = ctk.CTkFrame(controls, fg_color="transparent")
        action_frame.pack(fill="x", side="bottom", pady=(0, 20), padx=30)
        
        self.btn_gen_help = ctk.CTkButton(action_frame, text="View Tool Help", height=48, width=150, 
                                          command=self.show_yargen_help, fg_color="#202225", font=("Inter", 12, "bold"))
        self.btn_gen_help.pack(side="left", padx=(0, 10))

        self.btn_generate = ctk.CTkButton(action_frame, text="Generate YARA Rule", height=48, command=self.run_yargen, 
                                         fg_color=CLR_SUCCESS, hover_color="#27AE60", font=("Inter", 13, "bold"))
        self.btn_generate.pack(side="left", fill="x", expand=True)

        # 3. Output Split (Logs vs Results)
        split = ctk.CTkFrame(view, fg_color="transparent")
        split.pack(fill="both", expand=True)
        split.grid_columnconfigure(0, weight=4) # Console Logs
        split.grid_columnconfigure(1, weight=6) # Result Rule
        split.grid_rowconfigure(0, weight=1)

        # Console Logs (Left)
        console_box = ctk.CTkFrame(split, fg_color=CLR_CARD, corner_radius=15, border_width=1, border_color="#1E232E")
        console_box.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        ctk.CTkLabel(console_box, text="OUTPUT CONSOLE", font=("Inter", 11, "bold"), text_color=CLR_TEXT_DIM).pack(pady=10)
        self.gen_out = ctk.CTkTextbox(console_box, fg_color="transparent", font=("Consolas", 12), text_color="#A9B7C6")
        self.gen_out.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.log_to_textbox(self.gen_out, "[*] yarGen module online. Ready for blueprinting.\n")

        # Generated Result (Right)
        res_box = ctk.CTkFrame(split, fg_color="#0D1117", corner_radius=15, border_width=1, border_color="#30363D")
        res_box.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        ctk.CTkLabel(res_box, text="GENERATED YARA RULE", font=("Inter", 11, "bold"), text_color=CLR_ACCENT).pack(pady=10)
        self.gen_res = ctk.CTkTextbox(res_box, fg_color="transparent", font=("Cascadia Code", 13), undo=True)
        self.gen_res.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
    def log_gen(self, msg, type="info"):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = "[*]"
        if type == "success": prefix = "[+]"
        elif type == "error": prefix = "[!]"
        elif type == "warn": prefix = "[-]"
        self.log_to_textbox(self.gen_out, f"[{ts}] {prefix} {msg}\n")

    def pick_yargen_path(self):
        f = filedialog.askopenfilename(title="Select yargen.exe", filetypes=[("Executables", "*.exe"), ("All Files", "*.*")])
        if f:
            self.yargen_path.set(f)
            self.save_app_settings()

    def pick_gen_sample(self):
        d = filedialog.askdirectory(title="Select Malware Samples Folder")
        if d: self.gen_sample_path.set(d)

    def show_yargen_help(self):
        exe = self.yargen_path.get()
        if not os.path.exists(exe) or "Not Configured" in exe:
            messagebox.showwarning("System Check", "yargen.exe path is invalid. Please use the 'Browse Tool' button to select it.")
            return

        def task():
            try:
                self.after(0, lambda: self.log_gen("Fetching tool help information...", "info"))
                proc = subprocess.run([exe, "-h"], capture_output=True, text=True, cwd=str(Path(exe).parent))
                output = proc.stdout if proc.stdout else proc.stderr
                if output:
                    self.after(0, lambda o=output: (
                        self.log_to_textbox(self.gen_out, f"\n--- YARGEN TOOL HELP ---\n{o}\n"),
                        self.log_gen("Help output displayed in console.", "success")
                    ))
                else:
                    self.after(0, lambda: self.log_gen("Tool returned no help output.", "warn"))
            except Exception as e:
                self.after(0, lambda e=e: self.log_gen(f"Help Error: {str(e)}", "error"))

        threading.Thread(target=task, daemon=True).start()

    def run_yargen(self):
        if self.is_generating: return
        exe = self.yargen_path.get()
        samples = self.gen_sample_path.get()
        
        if not os.path.exists(exe) or "Not Configured" in exe:
            messagebox.showwarning("System Check", "yargen.exe path is invalid. Please use the 'Browse Tool' button to select it.")
            return
        
        if not os.path.isdir(samples) or "Select folder" in samples:
            messagebox.showwarning("Target Check", "Please select a valid folder of samples to analyze.")
            return

        def task():
            self.is_generating = True
            yargen_dir = Path(exe).parent
            output_file = yargen_dir / "yargen_rule_output.txt"
            
            try:
                self.after(0, lambda: self.btn_generate.configure(state="disabled", text="GENERATING..."))
                self.log_gen(f"Initiating blueprinting on: {samples}", "info")
                
                # Command execution with CWD set to yargen's folder
                custom_flags = self.gen_custom_flags.get().strip()
                # Essential flags: -m for samples, -o for output
                cmd = [exe, "-m", samples, "-o", str(output_file)]
                
                # Append user flags from the UI (e.g. --score, --super-rules)
                if custom_flags:
                    try:
                        # Use shlex to correctly parse flags (handling quotes etc.)
                        added_flags = shlex.split(custom_flags)
                        cmd.extend(added_flags)
                    except:
                        # Fallback to simple split if shlex fails
                        cmd.extend(custom_flags.split())

                self.log_gen(f"Executing: {' '.join(cmd)}", "info")
                
                # We use Popen to capture output if possible, but yargen-go might be quiet
                proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(yargen_dir))
                if proc.stdout: self.log_gen(proc.stdout.strip(), "info")
                if proc.stderr: self.log_gen(proc.stderr.strip(), "warn")
                
                if output_file.exists():
                    rule_content = output_file.read_text(encoding='utf-8', errors='ignore')
                    self.after(0, lambda c=rule_content: (
                        self.gen_res.delete("1.0", "end"), 
                        self.gen_res.insert("1.0", c),
                        self.highlight_yara_content(self.gen_res, c)
                    ))
                    self.log_gen("Generation Complete. Rule loaded into display.", "success")
                    # Clean up the output file from yargen folder
                    try: output_file.unlink()
                    except: pass
                else:
                    self.log_gen("Error: Output file was not generated.", "error")
            except Exception as e:
                self.log_gen(f"Critical Failure: {str(e)}", "error")
            finally:
                self.is_generating = False
                self.after(0, lambda: self.btn_generate.configure(state="normal", text="GENERATE RULE"))

        threading.Thread(target=task, daemon=True).start()

    def create_search_view(self):
        view = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.views["search"] = view
        
        # 1. Header
        header = ctk.CTkFrame(view, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="YARA Search", font=("Inter", 24, "bold")).pack()
        ctk.CTkLabel(header, text="High-performance rule discovery across all repositories", 
                     text_color=CLR_TEXT_DIM, font=("Inter", 12)).pack()

        # 2. Search Controls
        controls = ctk.CTkFrame(view, fg_color=CLR_CARD, corner_radius=15, border_width=1, border_color="#1E232E")
        controls.pack(fill="x", pady=(0, 20))
        
        inner = ctk.CTkFrame(controls, fg_color="transparent")
        inner.pack(fill="x", padx=30, pady=20)
        inner.grid_columnconfigure(1, weight=1)

        # Folder Selection Row
        ctk.CTkLabel(inner, text="LIBRARY FOLDER:", font=self.emoji_font_bold, text_color=CLR_ACCENT).grid(row=0, column=0, padx=(0, 15), sticky="w")
        ctk.CTkLabel(inner, textvariable=self.search_path, fg_color=CLR_BG, corner_radius=10, height=35, anchor="w", padx=15).grid(row=0, column=1, sticky="ew", pady=(0, 10))
        
        folder_btns = ctk.CTkFrame(inner, fg_color="transparent")
        folder_btns.grid(row=0, column=2, padx=(15, 0), pady=(0, 10))
        ctk.CTkButton(folder_btns, text="Browse", width=80, height=32, command=self.pick_search_folder).pack(side="left", padx=(0, 5))
        ctk.CTkButton(folder_btns, text="Reset", width=60, height=32, fg_color="#202225", command=lambda: (self.search_path.set("Default (./Master Rules)"), setattr(self, 'search_index', []))).pack(side="left")

        # Search Query Row
        ctk.CTkLabel(inner, text="SEARCH QUERY:", font=self.emoji_font_bold, text_color=CLR_ACCENT).grid(row=1, column=0, padx=(0, 15), sticky="w")
        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(inner, textvariable=self.search_var, placeholder_text="Enter keyword, rule name, or meta info...",
                                        height=40, font=("Inter", 13), fg_color=CLR_BG, border_color="#30363D")
        self.search_entry.grid(row=1, column=1, sticky="ew")
        self.search_entry.bind("<Return>", lambda e: self.run_search())
        
        ctk.CTkButton(inner, text="Search Rules", width=155, height=40, font=("Inter", 12, "bold"),
                      command=self.run_search, fg_color=CLR_ACCENT, hover_color="#4752C4").grid(row=1, column=2, padx=(15, 0))

        # 3. Main Display (Split)
        split = ctk.CTkFrame(view, fg_color="transparent")
        split.pack(fill="both", expand=True)
        split.grid_columnconfigure(0, weight=5, uniform="search_split") # Table
        split.grid_columnconfigure(1, weight=5, uniform="search_split") # Code View
        split.grid_rowconfigure(0, weight=1)

        # Result Table (Left)
        res_container = ctk.CTkFrame(split, fg_color=CLR_CARD, corner_radius=15, border_width=1, border_color="#1E232E")
        res_container.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        self.search_tree = self.create_table(res_container, ["#", "Rule Name", "Author", "Description"])
        self.search_tree.bind("<<TreeviewSelect>>", self.on_search_select)

        # Preview Code (Right)
        preview_box = ctk.CTkFrame(split, fg_color="#0D1117", corner_radius=15, border_width=1, border_color="#30363D")
        preview_box.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        
        ctk.CTkLabel(preview_box, text="RULE PREVIEW", font=("Inter", 11, "bold"), text_color=CLR_ACCENT).pack(pady=10)
        self.search_preview = ctk.CTkTextbox(preview_box, fg_color="transparent", font=("Cascadia Code", 13), border_width=0)
        self.search_preview.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def run_search(self):
        query = self.search_var.get().strip().lower()
        if not query: return
        
        # Internal indexing if first run or empty
        base_dir = Path(__file__).parent.parent if not getattr(sys, 'frozen', False) else Path(sys.executable).parent
        MASTER_DIR = base_dir / "Master Rules"
        STORAGE_DIR = base_dir / "Downloaded Public Rules"
        QUARANTINE_DIR = base_dir / "Problematic Rules"
        ENV_SPECIFIC_DIR = base_dir / "Environment-specific Rules"
        FIXED_DIR = base_dir / "Fixed Rules"
        
        master_file = MASTER_DIR / "public_master_rules.yara"
        
        if not self.search_index:
            self.update_status("Indexing rule library... might take a moment", "ok")
            indexed_contents = set() # To avoid duplicate content
            
            def index_file(f_path):
                try:
                    content = f_path.read_text(encoding='utf-8', errors='ignore')
                    # Split into rules
                    rules = re.findall(r'(?m)^((?:(?:global|private)\s+)?rule\s+([\w\.]+).*?\{.*?^\})', content, re.DOTALL | re.MULTILINE)
                    for full_rule, rname in rules:
                        # Deduplicate by content hash or just content
                        r_hash = hash(full_rule)
                        if r_hash in indexed_contents: continue
                        indexed_contents.add(r_hash)

                        author = ""
                        desc = ""
                        auth_m = re.search(r'author\s*=\s*"(.*?)"', full_rule, re.IGNORECASE)
                        if auth_m: author = auth_m.group(1)
                        desc_m = re.search(r'description\s*=\s*"(.*?)"', full_rule, re.IGNORECASE)
                        if desc_m: desc = desc_m.group(1)
                        
                        self.search_index.append({
                            "name": rname,
                            "author": author,
                            "desc": desc,
                            "content": full_rule,
                            "source": f_path.name
                        })
                except:
                    pass

            # 1. Index Master File if it exists (only if searching all)
            custom_path = self.search_path.get()
            is_default = "All Repositories" in custom_path

            if is_default:
                if master_file.exists():
                    index_file(master_file)

                # 2. Index all folders and subfolders
                for d in [MASTER_DIR, STORAGE_DIR, QUARANTINE_DIR, ENV_SPECIFIC_DIR, FIXED_DIR]:
                    if d.exists():
                        for f in d.rglob("*.yar*"):
                            if f.resolve() == master_file.resolve(): continue
                            index_file(f)
            else:
                # Index custom path
                d = Path(custom_path)
                if d.exists():
                    for f in d.rglob("*.yar*"):
                        index_file(f)
        
        if not self.search_index:
            messagebox.showwarning("Search Rules", "No rules found in library. Run 'Pull Rules' first.")
            return

        # Clear existing
        for item in self.search_tree.get_children(): self.search_tree.delete(item)
        
        results = []
        for r in self.search_index:
            # Multi-field search
            if (query in r["name"].lower() or 
                query in r["author"].lower() or 
                query in r["desc"].lower() or
                query in r["content"].lower()):
                results.append(r)
        
        for i, r in enumerate(results):
            # Show search results
            self.search_tree.insert("", "end", values=(i+1, r["name"], r["author"], r["desc"]))
        
        self.auto_fit_columns(self.search_tree)
        self.update_status(f"Found {len(results)} rules matching '{query}'", "ok")

    def on_search_select(self, event):
        sel = self.search_tree.selection()
        if not sel: return
        rname = self.search_tree.item(sel[0], "values")[1]
        
        # Find in index
        rule_data = next((r for r in self.search_index if r["name"] == rname), None)
        if rule_data:
            self.search_preview.configure(state="normal")
            self.search_preview.delete("1.0", "end")
            self.search_preview.insert("1.0", rule_data["content"])
            
            self.highlight_yara_content(self.search_preview, rule_data["content"])
            self.search_preview.configure(state="disabled")

    def btn_lab_command(self):
        self.select_tab("lab")

    def on_editor_change(self, event=None):
        if self.check_editor_limits(): return
        self.trigger_highlighting()
        # De-bounce line number redraw for performance
        if hasattr(self, "_redraw_timer"): self.after_cancel(self._redraw_timer)
        self._redraw_timer = self.after(50, self.redraw_line_numbers)

    def check_editor_limits(self, content=None):
        if content is None: content = self.lab_editor.get("1.0", "end-1c")
        line_count = int(self.lab_editor._textbox.index('end-1c').split('.')[0])
        
        limit_lines = 100000
        limit_size = 5 * 1024 * 1024 # 5MB
        
        if line_count > limit_lines or len(content) > limit_size:
            messagebox.showwarning("File Size Limit Exceeded", 
                                 f"Safety Alert:\n\n"
                                 f"The rule set is too large for the interactive editor.\n"
                                 f"Maximum Supported: {limit_lines:,} lines / 5MB.\n\n"
                                 f"Please split your rule files for analysis.")
            return True
        return False

    def redraw_line_numbers(self):
        self.line_numbers.delete("all")
        i = self.lab_editor._textbox.index("@0,0")
        while True:
            dline = self.lab_editor._textbox.dlineinfo(i)
            if dline is None: break
            y = dline[1]
            linenum = str(i).split(".")[0]
            self.line_numbers.create_text(30, y, anchor="ne", text=linenum, fill="#4B5263", font=("Cascadia Code", 11))
            i = self.lab_editor._textbox.index(f"{i} + 1line")

    def trigger_highlighting(self, event=None):
        if hasattr(self, "_highlight_timer"):
            self.after_cancel(self._highlight_timer)
        self._highlight_timer = self.after(300, self.apply_highlighting)

    def apply_highlighting(self, force=False):
        content = self.lab_editor.get("1.0", "end-1c")
        
        # Technical Cleanse
        for tag in ["kw", "str", "com", "var", "hex", "regex", "num"]:
            self.lab_editor.tag_remove(tag, "1.0", "end")

        # 1. Basic Keywords
        kw_pattern = r'\b(rule|meta|strings|condition|import|include|global|private|all|any|of|them|and|or|not|at|in|filesize|entrypoint|startswith|endswith|contains|icase|fullword|wide|ascii|xor|base64|base64wide|nocase)\b'
        for match in re.finditer(kw_pattern, content):
            self.lab_editor.tag_add("kw", f"1.0 + {match.start()} c", f"1.0 + {match.end()} c")

        # 2. Rule Modules & Types
        intel_pattern = r'\b(pe|elf|math|hash|dotnet|macho|dex|magic|time|console|uint8|uint16|uint32|uint8be|uint16be|uint32be|int8|int16|int32|int8be|int16be|int32be)\b'
        for match in re.finditer(intel_pattern, content):
             self.lab_editor.tag_add("num", f"1.0 + {match.start()} c", f"1.0 + {match.end()} c")

        # 3. Numeric Literals & Booleans
        for match in re.finditer(r'\b(0x[0-9a-fA-F]+|0b[01]+|\d+|true|false)\b', content):
            self.lab_editor.tag_add("num", f"1.0 + {match.start()} c", f"1.0 + {match.end()} c")

        # 4. Variables & IDs
        for match in re.finditer(r'[\$\#\@]\w*', content):
            self.lab_editor.tag_add("var", f"1.0 + {match.start()} c", f"1.0 + {match.end()} c")

        # 5. Regex Literals (Surgical Isolation)
        for match in re.finditer(r'/(?:\\.|[^\n\/\\])+/i?', content):
             if not content[match.start():match.start()+2] == '//':
                self.lab_editor.tag_add("regex", f"1.0 + {match.start()} c", f"1.0 + {match.end()} c")

        # 6. Strings (Escape Aware)
        for match in re.finditer(r'"(?:\\.|[^"\\])*"', content):
            self.lab_editor.tag_add("str", f"1.0 + {match.start()} c", f"1.0 + {match.end()} c")

        # 7. Hex String Arrays
        for match in re.finditer(r'\{[a-fA-F0-9\s\?\!\|]+\}', content):
            self.lab_editor.tag_add("hex", f"1.0 + {match.start()} c", f"1.0 + {match.end()} c")

        # 8. Rule Comments (Total Priority Override)
        for match in re.finditer(r'//.*$|/\*[\s\S]*?\*/', content, re.MULTILINE):
            st, en = f"1.0 + {match.start()} c", f"1.0 + {match.end()} c"
            for t in ["kw", "str", "var", "hex", "regex", "num"]: self.lab_editor.tag_remove(t, st, en)
            self.lab_editor.tag_add("com", st, en)

    def highlight_yara_content(self, textbox, content):
        textbox.tag_config("kw", foreground=CLR_ACCENT)
        textbox.tag_config("str", foreground=CLR_SUCCESS)
        textbox.tag_config("com", foreground=CLR_TEXT_DIM)
        textbox.tag_config("var", foreground="#FF79C6")
        textbox.tag_config("hex", foreground="#BD93F9")
        textbox.tag_config("regex", foreground="#F4A261")
        textbox.tag_config("num", foreground="#E9C46A")
        
        for tag in ["kw", "str", "com", "var", "hex", "regex", "num"]:
            textbox.tag_remove(tag, "1.0", "end")
            
        patterns = [
            ("kw", r'\b(rule|meta|strings|condition|import|include|global|private|all|any|of|them|and|or|not|at|in|filesize|entrypoint|startswith|endswith|contains|icase|fullword|wide|ascii|xor|base64|base64wide|nocase)\b'),
            ("num", r'\b(0x[0-9a-fA-F]+|0b[01]+|\d+|true|false)\b'),
            ("var", r'[\$\#\@]\w*'),
            ("str", r'"(?:\\.|[^"\\])*"'),
            ("hex", r'\{[a-fA-F0-9\s\?\!\|]+\}'),
            ("regex", r'/(?:\\.|[^\n\/\\])+/i?'),
            ("com", r'//.*$|/\*[\s\S]*?\*/')
        ]
        for tag, pattern in patterns:
            for m in re.finditer(pattern, content, re.MULTILINE if tag=="com" else 0):
                textbox.tag_add(tag, f"1.0 + {m.start()} c", f"1.0 + {m.end()} c")

    def get_md5(self, path):
        try:
            h = hashlib.md5()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except: return "Error"

    def select_tab(self, name):
        for v in self.views.values(): v.pack_forget()
        self.views[name].pack(fill="both", expand=True)
        
        # Style active button
        self.btn_analysis.configure(fg_color=CLR_ACCENT if name=="analysis" else "transparent")
        self.btn_lab.configure(fg_color=CLR_ACCENT if name=="lab" else "transparent")
        self.btn_collector.configure(fg_color=CLR_ACCENT if name=="collector" else "transparent")
        self.btn_generator.configure(fg_color=CLR_ACCENT if name=="generator" else "transparent")
        self.btn_search.configure(fg_color=CLR_ACCENT if name=="search" else "transparent")

    def log_to_textbox(self, textbox, msg, clear=False):
        textbox.configure(state="normal")
        if clear: textbox.delete("1.0", "end")
        textbox.insert("end", msg)
        textbox.see("end")
        textbox.configure(state="disabled")

    def update_lab_layout(self, mode):
        self.lab_view_mode = mode
        
        # Reset colors
        self.btn_layout_split.configure(fg_color="transparent", border_width=1)
        self.btn_layout_editor.configure(fg_color="transparent", border_width=1)
        self.btn_layout_results.configure(fg_color="transparent", border_width=1)
        
        if mode == "editor":
            self.lab_right_pane.place_forget()
            self.lab_left_pane.place(relx=0, rely=0, relwidth=1.0, relheight=1.0)
            self.btn_layout_editor.configure(fg_color=CLR_ACCENT, border_width=0)
        
        elif mode == "results":
            self.lab_left_pane.place_forget()
            self.lab_right_pane.place(relx=0, rely=0, relwidth=1.0, relheight=1.0)
            self.btn_layout_results.configure(fg_color=CLR_ACCENT, border_width=0)
            
        else: # split
            self.lab_left_pane.place(relx=0, rely=0, relwidth=0.45, relheight=1.0)
            self.lab_right_pane.place(relx=0.47, rely=0, relwidth=0.53, relheight=1.0)
            self.btn_layout_split.configure(fg_color=CLR_ACCENT, border_width=0)

    def update_lab_buttons_state(self):
        # Disable Save if path is the placeholder "File" or empty
        path = self.lab_rule_path.get()
        if not path or path == "File":
            self.btn_save_lab.configure(state="disabled", text_color=CLR_TEXT_DIM)
        else:
            self.btn_save_lab.configure(state="normal", text_color="white")

    def update_status(self, msg, type="ok"):
        color = CLR_SUCCESS if type=="ok" else CLR_ERROR
        self.status_label.configure(text=msg, text_color=color)

    def pick_lab_rule_file(self):
        f = filedialog.askopenfilename(filetypes=[("YARA Rules", "*.yar *.yara"), ("All Files", "*.*")])
        if f:
            self.lab_rule_path.set(f)
            try:
                content = Path(f).read_text(encoding='utf-8', errors='ignore')
                self.lab_editor.delete("1.0", "end")
                self.lab_editor.insert("1.0", content)
                self.on_editor_change()
                self.update_lab_buttons_state()
                self.lab_status.configure(text=f"SUCCESS: Rule loaded from {os.path.basename(f)}", text_color=CLR_SUCCESS)
            except Exception as e:
                self.lab_status.configure(text=f"ERROR: Failed to load rule file: {str(e)[:40]}", text_color=CLR_ERROR)

    def save_lab_rule(self, as_new=False):
        content = self.lab_editor.get("1.0", "end-1c")
        path = self.lab_rule_path.get()
        
        if as_new or not path or path.startswith("Optional:"):
            f = filedialog.asksaveasfilename(defaultextension=".yar", 
                                             initialfile="new_rule.yar",
                                             filetypes=[("YARA Rules", "*.yar"), ("All Files", "*.*")])
            if not f: return
            path = f
            self.lab_rule_path.set(path)

        try:
            Path(path).write_text(content, encoding='utf-8')
            short_name = os.path.basename(path)
            self.update_lab_buttons_state()
            self.lab_status.configure(text=f"SUCCESS: Rules saved to {short_name}", text_color=CLR_SUCCESS)
            messagebox.showinfo("Rule Export", f"YARA rule successfully saved to:\n{path}")
        except Exception as e:
            err_msg = f"CRITICAL: Failed to save rule: {str(e)}"
            self.lab_status.configure(text=err_msg[:60], text_color=CLR_ERROR)
            messagebox.showerror("Export Failed", err_msg)

    def pick_file(self):
        f = filedialog.askopenfilename()
        if f: self.target_path.set(f)

    def pick_target_folder(self):
        d = filedialog.askdirectory()
        if d: self.target_path.set(d)

    def pick_folder(self):
        d = filedialog.askdirectory()
        if d: self.lab_path.set(d)

    def pick_lab_file(self):
        f = filedialog.askopenfilename()
        if f: self.lab_path.set(f)

    def pick_search_folder(self):
        d = filedialog.askdirectory(title="Select YARA Rules Repository to Search")
        if d:
            self.search_path.set(d)
            # Clear index to force re-indexing of the new path
            self.search_index = []
            self.update_status(f"Library set to: {os.path.basename(d)}", "ok")

    def run_file_scan(self):
        path = self.target_path.get()
        rules_dir = self.analysis_rules_path.get()
        
        if self.is_scanning: return
        if not os.path.exists(path) or path == "Select threat sample...":
            self.update_status("Error: Select a valid target", "error")
            return
        if not os.path.isdir(rules_dir) or rules_dir == "Select YARA rules directory...":
            self.update_status("Error: Select a valid rules directory", "error")
            return

        self.is_scanning = True
        self.animate_analysis_loader()
        self.clear_hits_gallery()
        self.log_to_textbox(self.analysis_out, f"[*] Target: {os.path.basename(path)}\n", clear=True)
        self.log_to_textbox(self.analysis_out, f"[*] Rules: {os.path.basename(rules_dir)}\n")
        
        def task():
            try:
                # 1. Recursive YARA loading
                yara_files = {}
                folder = Path(rules_dir)
                for p in folder.rglob("*"):
                    if p.is_file() and p.suffix.lower() in [".yara", ".yar"]:
                        ns = p.name
                        base_ns = ns
                        counter = 1
                        while ns in yara_files:
                            ns = f"{base_ns}_{counter}"
                            counter += 1
                        yara_files[ns] = str(p.absolute())
                
                if not yara_files:
                    self.after(0, lambda: self.log_to_textbox(self.analysis_out, "[!] No YARA files found in directory.\n"))
                    self.is_scanning = False
                    return

                self.after(0, lambda: self.log_to_textbox(self.analysis_out, f"[*] Compiling {len(yara_files)} YARA files...\n"))
                self.rules_mapping = yara_files
                rules = yara.compile(filepaths=yara_files)
                
                # 2. Scanning Execution
                self.after(0, lambda: self.log_to_textbox(self.analysis_out, "[*] Scan in progress...\n"))
                
                final_matches = [] # List of (filename, match_object)
                
                if os.path.isfile(path):
                    matches = rules.match(path)
                    for m in matches: final_matches.append((os.path.basename(path), m))
                else:
                    # Folder scan
                    target_folder = Path(path)
                    target_files = [p for p in target_folder.rglob("*") if p.is_file()]
                    total_f = len(target_files)
                    self.after(0, lambda: self.log_to_textbox(self.analysis_out, f"[*] Batch mode: {total_f} files detected.\n"))
                    
                    for i, pkg in enumerate(target_files):
                        try:
                            m_list = rules.match(str(pkg))
                            for m in m_list: final_matches.append((pkg.name, m))
                        except: pass
                        if i % 10 == 0:
                            self.after(0, lambda i=i, t=total_f: self.update_status(f"Scanning {i}/{t}...", "ok"))

                self.after(0, lambda: self.finish_file_scan(final_matches))
            except Exception as e:
                self.after(0, lambda: self.log_to_textbox(self.analysis_out, f"[ERROR] {str(e)}\n"))
                self.is_scanning = False

        threading.Thread(target=task, daemon=True).start()

    def finish_file_scan(self, final_results):
        # final_results: list of (filename, match_obj)
        def ui_update():
            self.is_scanning = False
            for widget in self.hits_gallery.winfo_children():
                widget.destroy()
            if hasattr(self, "hits_placeholder"):
                try: self.hits_placeholder.destroy()
                except: pass
                
            if not final_results:
                self.log_to_textbox(self.analysis_out, "[!] SCAN FINISHED: No matches found.\n")
                self.clear_hits_gallery()
            else:
                self.log_to_textbox(self.analysis_out, f"[!] ALERT: Found {len(final_results)} detections!\n")
                for fname, m in final_results:
                    self.log_to_textbox(self.analysis_out, f" -> [{fname}] Hit: {m.rule} (Source: {m.namespace})\n")
                    
                    # Attribution in badge text for better clarity
                    disp_name = fname if len(fname) < 20 else f"...{fname[-17:]}"
                    badge_text = f"⚠️ [{disp_name}] {m.rule}"
                    
                    badge = ctk.CTkButton(self.hits_gallery, text=badge_text, 
                                         font=("Inter", 12, "bold"), fg_color="#2D1616",
                                         border_width=1, border_color=CLR_ERROR, corner_radius=8,
                                         hover_color="#3D1C1C", height=42, anchor="w",
                                         command=lambda match_obj=m: self.display_rule_source(match_obj))
                    badge.pack(fill="x", padx=10, pady=5, side="top")
                
                self.after(100, self.toggle_gallery_scrollbar)
        self.after(0, ui_update)

    def display_rule_source(self, match):
        if hasattr(self, "rule_placeholder"):
            try: self.rule_placeholder.destroy()
            except: pass
            
        file_path = self.rules_mapping.get(match.namespace)
        
        if not file_path or not os.path.exists(file_path):
            content = f"// Error: Source file not found on disk for '{match.rule}'\n"
            content += f"// Expected path: {file_path}\n"
            file_size = 0
        else:
            try:
                file_size = os.path.getsize(file_path)
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                content = f"// Error: Could not read source file.\n// Reason: {str(e)}\n"
                file_size = 0
        
        if file_size > 0:
            try:
                # Surgical extraction of the rule block
                import re
                pattern = rf"rule\s+{re.escape(match.rule)}\b"
                start_search = re.search(pattern, content)
                if start_search:
                    start_ptr = start_search.start()
                    # Find the first opening brace after the rule name
                    brace_start = content.find("{", start_ptr)
                    if brace_start != -1:
                        balance = 0
                        end_ptr = brace_start
                        # Brace balancing logic to find the end of the block
                        for i in range(brace_start, len(content)):
                            if content[i] == '{': balance += 1
                            elif content[i] == '}': balance -= 1
                            
                            if balance <= 0 and i > brace_start:
                                end_ptr = i + 1
                                break
                        content = content[start_ptr:end_ptr].strip()
            except Exception as e:
                self.log_to_textbox(self.analysis_out, f"[!] Extraction error: {str(e)}\n")
        
        self.view_editor.configure(state="normal")
        self.view_editor.delete("1.0", "end")
        self.view_editor.insert("1.0", content)
        
        # Snippets are small, always highlight
        self.apply_view_highlighting()

        self.view_editor.configure(state="disabled")

    def apply_view_highlighting(self):
        content = self.view_editor.get("1.0", "end-1c")
        for tag in ["kw", "str", "hex", "var", "com", "num", "regex"]: 
            self.view_editor.tag_remove(tag, "1.0", "end")
        
        self.view_editor.tag_config("kw", foreground="#5865F2")
        self.view_editor.tag_config("str", foreground="#00D166")
        self.view_editor.tag_config("hex", foreground="#BD93F9")
        self.view_editor.tag_config("var", foreground="#FF79C6")
        self.view_editor.tag_config("com", foreground="#8E9297")
        self.view_editor.tag_config("num", foreground="#E9C46A")
        self.view_editor.tag_config("regex", foreground="#F4A261")

        # Rule Pattern Priority
        patterns = [
            ("com", r'//.*$|/\*[\s\S]*?\*/'),
            ("kw", r'\b(rule|meta|strings|condition|import|include|global|private|all|any|of|them|and|or|not|at|in|filesize|entrypoint|startswith|endswith|contains|icase|fullword|wide|ascii|xor|base64|base64wide|nocase|pe|elf|math|hash|dotnet|macho|dex|magic|time|console|archive|cuckoo)\b'),
            ("num", r'\b(0x[0-9a-fA-F]+|0b[01]+|\d+|true|false|pe|elf|math|hash|dotnet|macho|dex|magic|time|console|uint8|uint16|uint32|uint8be|uint16be|uint32be|int8|int16|int32|int8be|int16be|int32be)\b'),
            ("var", r'[\$\#\@]\w*'),
            ("str", r'"(?:\\.|[^"\\])*"'),
            ("hex", r'\{[a-fA-F0-9\s\?\!\|]+\}'),
            ("regex", r'/(?:\\.|[^\n\/\\])+/i?')
        ]

        for tag, pattern in patterns:
            for match in re.finditer(pattern, content, re.MULTILINE if tag=="com" else 0):
                if tag == "regex" and content[match.start():match.start()+2] == '//': continue
                self.view_editor.tag_add(tag, f"1.0 + {match.start()} c", f"1.0 + {match.end()} c")

    def lab_check_syntax(self, silent=False):
        raw = self.lab_editor.get("1.0", "end-1c").strip()
        if not raw: return None
        try:
            # Dynamic module detection
            available_mods = set(yara.modules)
            test_mods = ["pe", "elf", "math", "hash", "dotnet", "macho", "dex", "magic", "time", "console"]
            active_mods = [m for m in test_mods if m in available_mods]
            import_count = len(active_mods)
            imports = '\n'.join([f'import "{m}"' for m in active_mods]) + '\n'
            
            try:
                # First pass: Check exactly as written (unpolluted line numbers)
                compiled = yara.compile(source=raw)
            except yara.SyntaxError as e:
                try:
                    # Second pass: Auto-inject imports if missing (pollutes line numbers)
                    compiled = yara.compile(source=imports + raw)
                except yara.SyntaxError as e2:
                    # If it fails even with imports, adjust the line number back to editor coordinates
                    err_msg = str(e2)
                    # Handle "(line): msg" and "line line: msg" formats
                    match = re.search(r'\((\d+)\):', err_msg)
                    if not match: match = re.search(r'line (\d+):', err_msg)
                    
                    if match:
                        orig_line = int(match.group(1))
                        # Offset is import_count (one per line) + 1 for the extra newline we added
                        real_line = orig_line - (import_count + 1)
                        if real_line > 0:
                            err_msg = err_msg.replace(f"({orig_line}):", f"({real_line}):")
                            err_msg = err_msg.replace(f"line {orig_line}:", f"line {real_line}:")
                    raise Exception(err_msg)
            
            if not silent:
                self.lab_status.configure(text="STATUS: Valid Rule Structure", text_color="#2ECC71")
                # Force highlight on successful check even if large file (Safe as it's not on every keystroke)
                self.apply_highlighting(force=True)
            return compiled
        except Exception as e:
            err_msg = str(e)
            if not silent:
                self.lab_status.configure(text=f"ERROR: {err_msg}", text_color=CLR_ERROR)
            return None

    def fix_rule_ai(self):
        # 1. State check
        if self.is_scanning: return
        
        # 2. Load AI Config
        base_dir = Path(__file__).parent.parent if not getattr(sys, 'frozen', False) else Path(sys.executable).parent
        cfg_path = base_dir / "config" / "AI.cfg"
        
        import json
        try:
            if not cfg_path.exists():
                cfg_path.parent.mkdir(parents=True, exist_ok=True)
                cfg_path.write_text('{"base_url": "https://api.openai.com/v1", "api_key": "", "model": "gpt-4o"}')
            ai_cfg = json.loads(cfg_path.read_text())
        except:
            ai_cfg = {"base_url": "https://api.openai.com/v1", "api_key": "", "model": "gpt-4o"}
            
        api_key = ai_cfg.get("api_key")
        if not api_key:
            messagebox.showerror("AI Error", "No API Key found in config/AI.cfg")
            return

        # 3. Identify Error
        raw = self.lab_editor.get("1.0", "end-1c").strip()
        if not raw:
            messagebox.showinfo("AI Fix", "The editor is empty. Please enter a rule to fix.")
            return

        error_msg = "Unknown validation error"
        try:
            available_mods = set(yara.modules) if hasattr(yara, 'modules') else set()
            test_mods = ["pe", "elf", "math", "hash", "dotnet", "macho", "dex", "magic", "time", "console"]
            active_imps = '\n'.join([f'import "{m}"' for m in test_mods if m in available_mods]) + '\n'
            yara.compile(source=active_imps + raw)
            messagebox.showinfo("AI Fix", "The YARA rule is already syntactically valid!")
            return
        except Exception as e:
            error_msg = str(e)

        # 4. AI Repair Request
        def task():
            try:
                self.after(0, lambda: self.update_status("AI is analyzing rule...", "warn"))
                self.after(0, lambda: self.lab_status.configure(text="✨ AI Repair in progress...", text_color="#BD93F9"))
                
                prompt = f"Fix the following YARA rule. It has a syntax error: {error_msg}\n\n### RULE CONTENT ###\n{raw}\n\n### FIXED RULE ###\nReturn ONLY the corrected YARA rule content. No markdown, no explanations."
                
                headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                payload = {
                    "model": ai_cfg.get("model", "gpt-4o"),
                    "messages": [
                        {"role": "system", "content": "You are a world-class YARA engineer. Fix errors so they compile perfectly. Return only the code."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.2
                }
                
                response = requests.post(f"{ai_cfg.get('base_url','https://api.openai.com/v1')}/chat/completions", 
                                       headers=headers, json=payload, timeout=45)
                
                if response.status_code == 200:
                    fixed = response.json()['choices'][0]['message']['content'].strip()
                    fixed = re.sub(r'^```(yara)?\n?', '', fixed)
                    fixed = re.sub(r'\n?```$', '', fixed)
                    
                    self.after(0, lambda f=fixed: (
                        self.lab_editor.delete("1.0", "end"),
                        self.lab_editor.insert("1.0", f),
                        self.apply_highlighting(),
                        self.update_status("AI Repair successful", "ok"),
                        self.lab_status.configure(text="Rule repaired by AI", text_color=CLR_SUCCESS)
                    ))
                else:
                    err_hint = response.json().get('error', {}).get('message', 'API Error')
                    self.after(0, lambda msg=err_hint: messagebox.showerror("Service Error", f"OpenAI API error: {msg}"))
                    self.after(0, lambda: (
                        self.update_status("AI Fix failed", "error"),
                        self.lab_status.configure(text="AI repair failed", text_color=CLR_ERROR)
                    ))
            except Exception as ex:
                self.after(0, lambda msg=str(ex): messagebox.showerror("Repair Failure", f"Critical error: {msg}"))
                self.after(0, lambda: (
                    self.update_status("AI Fix failed", "error"),
                    self.lab_status.configure(text="Critical repair error", text_color=CLR_ERROR)
                ))

        threading.Thread(target=task, daemon=True).start()

    def run_batch_scan(self):
        if self.is_scanning: 
            messagebox.showinfo("Scanner Busy", "A scan is already in progress. Please wait.")
            return

        # 1. Syntax Check with Feedback
        rules = self.lab_check_syntax(silent=False)
        if not rules: 
            self.lab_status.configure(text="ERROR: Cannot scan with invalid rules", text_color=CLR_ERROR)
            return
        
        # 2. Target Validation (Folder or File)
        target = self.lab_path.get()
        placeholder = "Select target folder containing samples..."
        if not os.path.exists(target) or target == placeholder:
            self.update_status("Error: Select a valid target", "error")
            messagebox.showwarning("Target Required", "Please select a valid folder or file to scan.")
            return

        self.is_scanning = True
        
        # Clear tables
        for item in self.hit_tree.get_children(): self.hit_tree.delete(item)
        for item in self.clean_tree.get_children(): self.clean_tree.delete(item)
        self.log_to_textbox(self.summary_box, "", clear=True)
        self.res_view.set("Detections")
        
        # Track hit efficacy
        raw_rule = self.lab_editor.get("1.0", "end-1c")
        all_rule_names = re.findall(r'rule\s+([\w\.]+)', raw_rule)
        rule_stats = {name: 0 for name in all_rule_names}

        self.log_to_textbox(self.summary_box, f"[*] Starting Batch Scan\n[*] Target: {target}\n\n")

        def task():
            try:
                if os.path.isdir(target):
                    f_paths = [p for p in Path(target).rglob("*") if p.is_file()]
                else:
                    f_paths = [Path(target)]
                total = len(f_paths)
                self.after(0, lambda: self.log_to_textbox(self.summary_box, f"[*] Found {total} files. Starting scan...\n"))
                
                hits_total = 0
                clean_count = 0
                clean_files_list = []
                
                for i, p in enumerate(f_paths):
                    try:
                        matches = rules.match(str(p))
                        p_abs = str(p.absolute())
                        md5 = self.get_md5(p_abs)
                        if matches:
                            hits_total += 1
                            rnames = ", ".join([m.rule for m in matches])
                            for m in matches: rule_stats[m.rule] += 1
                            # Real-time Hit insertion with MD5 and row number
                            self.after(0, lambda n=p.name, r=rnames, h=md5, f=p_abs, idx=hits_total: 
                                        self.hit_tree.insert("", "end", values=(idx, n, r, h, f)))
                        else:
                            clean_count += 1
                            clean_files_list.append((clean_count, p.name, md5, p_abs))
                        
                        if i % 10 == 0:
                            self.after(0, lambda i=i, t=total: self.update_status(f"Scanning... {i}/{t}", "ok"))
                    except: pass

                def finalize():
                    # Batch insert Clean files for performance
                    for idx, name, md5, path in clean_files_list:
                        self.clean_tree.insert("", "end", values=(idx, name, md5, path))

                    # Auto-fit columns based on new data
                    self.auto_fit_columns(self.hit_tree)
                    self.auto_fit_columns(self.clean_tree)

                    self.is_scanning = False
                    self.log_to_textbox(self.summary_box, f"=== SCAN FINISHED ===\n")
                    self.log_to_textbox(self.summary_box, f"Files Scanned: {total}\n")
                    self.log_to_textbox(self.summary_box, f"Total Hits: {hits_total}\n\n")
                    
                    # Log Stats
                    hit_rank = sorted([(r, c) for r, c in rule_stats.items()], key=lambda x: x[1], reverse=True)
                    self.log_to_textbox(self.summary_box, "RULE EFFICACY:\n")
                    for r, count in hit_rank:
                        self.log_to_textbox(self.summary_box, f"  - {r}: {count} hits\n")
                    
                    if hits_total == 0:
                        self.after(0, lambda: self.res_view.set("Summary"))
                        self.update_status(f"Scan Complete: No hits found in {total} files", "ok")
                    else:
                        self.update_status(f"Scan Complete: {hits_total} hits / {total} files", "ok")
                    
                    self.lab_status.configure(text=f"FINISHED: {hits_total} hits found", text_color="#2ECC71")

                self.after(0, finalize)
            except Exception as e:
                self.after(0, lambda e=e: self.show_scan_error(str(e)))

        threading.Thread(target=task, daemon=True).start()

    def show_scan_error(self, err):
        self.update_status(f"Scan Error", "error")
        self.lab_status.configure(text=f"SCAN ERROR: {err}", text_color=CLR_ERROR)

    def clear_lab_results(self):
        for item in self.hit_tree.get_children(): self.hit_tree.delete(item)
        for item in self.clean_tree.get_children(): self.clean_tree.delete(item)
        self.log_to_textbox(self.summary_box, "", clear=True)
        self.update_status("Results cleared", "ok")

    def copy_all_md5s(self):
        active_tab = self.res_view.get()
        target_tree = None
        
        if active_tab == "Detections":
            target_tree = self.hit_tree
        elif active_tab == "Undetected":
            target_tree = self.clean_tree
            
        if not target_tree:
            self.update_status("Select target tab first", "error")
            return

        md5s = []
        cols = target_tree["columns"]
        if "MD5" in cols:
            idx = cols.index("MD5")
            for item in target_tree.get_children():
                md5s.append(target_tree.item(item, "values")[idx])
        
        if md5s:
            self.clipboard_clear()
            self.clipboard_append("\n".join(md5s))
            self.update_status(f"Copied {len(md5s)} MD5s from {active_tab}", "ok")
        else:
            self.update_status(f"No MD5s in {active_tab}", "error")

    def start_collection(self, mode="update"):
        if self.is_scanning: return
        
        if mode == "reset":
            if not messagebox.askyesno("Nuclear Reset", "Are you sure you want to WIPE all repositories? This will delete all downloaded and fixed rules."):
                return

        self.is_scanning = True
        self.btn_stop.configure(state="normal")
        for b in self.collector_action_btns: b.configure(state="disabled")
        self.animate_collector_loader()
        
        self.log_col(f"TASK STARTED: MODE = {mode.upper()}", "info")
        self.col_progress.set(0)
        self.abort_collection = False
        threading.Thread(target=self.collection_task, args=(mode,), daemon=True).start()

    def stop_collection(self):
        if self.is_scanning:
            self.abort_collection = True
            self.log_col("ABORT SIGNAL SENT. Terminating sequence...", "error")

    def collection_task(self, mode):
        if getattr(sys, 'frozen', False):
            base_dir = Path(sys.executable).parent
        else:
            base_dir = Path(__file__).parent.parent
        STORAGE_DIR, TEMP_DIR = base_dir / "Downloaded Public Rules", base_dir / "temp"
        MASTER_DIR = base_dir / "Master Rules"
        OUTPUT_FILE = MASTER_DIR / "public_master_rules.yara"
        QUARANTINE_DIR = base_dir / "Problematic Rules"
        ENV_SPECIFIC_DIR = base_dir / "Environment-specific Rules"
        FIXED_DIR = base_dir / "Fixed Rules"
        PROBLEMATIC_LIST_FILE = base_dir / "problematic_rules.txt"
        SOURCE_LOG_FILE = base_dir / "source_error_log.txt"
        SOURCES_FILE = base_dir / "config" / "yara_sources.txt"
        try:
            if mode == "reset":
                self.after(0, lambda: self.collector_status.set("Reset Started..."))
                self.log_col("Wiping all rule repositories...", "warn")
                for d in [STORAGE_DIR, TEMP_DIR, QUARANTINE_DIR, FIXED_DIR, ENV_SPECIFIC_DIR]:
                    if d.exists(): shutil.rmtree(d)
                if OUTPUT_FILE.exists(): OUTPUT_FILE.unlink()
                if PROBLEMATIC_LIST_FILE.exists(): PROBLEMATIC_LIST_FILE.unlink()
                if SOURCE_LOG_FILE.exists(): SOURCE_LOG_FILE.unlink()
                
                self.after(0, lambda: self.collector_status.set("Nuclear Reset Complete."))
                self.log_col("Task complete: All repositories wiped.", "success")
                self.after(0, lambda: self.col_progress.set(1))
                return # End here, do not download

            # Directory creation
            needed_dirs = [MASTER_DIR, QUARANTINE_DIR, ENV_SPECIFIC_DIR]
            if mode == "update": 
                needed_dirs += [STORAGE_DIR, TEMP_DIR]
            
            [d.mkdir(parents=True, exist_ok=True) for d in needed_dirs]

            if mode == "update":
                self.after(0, lambda: self.collector_status.set("Downloading Sources..."))
                sources = []
                if SOURCES_FILE.exists():
                    lines = SOURCES_FILE.read_text(encoding='utf-8').splitlines()
                    sources = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
                
                if not sources:
                    # Fallback to defaults if file missing or empty
                    sources = [
                        "https://github.com/anyrun/YARA",
                        "https://github.com/AlienVault-Labs/AlienVaultLabs",
                        "https://github.com/bartblaze/Yara-rules",
                        "https://github.com/codewatchorg/Burp-Yara-Rules",
                        "https://github.com/jipegit/yara-rules-public",
                        "https://github.com/securitymagic/yara",
                        "https://github.com/t4d/PhishingKit-Yara-Rules",
                        "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules",
                        "https://github.com/tjnel/yara_repo",
                        "https://github.com/VectraThreatLab/reyara",
                        "https://github.com/fr0gger/Yara-Unprotect",
                        "https://github.com/stvemillertime/ConventionEngine",
                        "https://github.com/filescanio/fsYara",
                        "https://github.com/h3x2b/yara-rules",
                        "https://github.com/imp0rtp3/yara-rules",
                        "https://github.com/intezer/yara-rules",
                        "https://github.com/InQuest/yara-rules",
                        "https://github.com/jeFF0Falltrades/YARA-Signatures",
                        "https://github.com/kevthehermit/YaraRules",
                        "https://github.com/Hestat/lw-yara",
                        "https://github.com/MalGamy/YARA_Rules",
                        "https://github.com/S12cybersecurity/YaraRules",
                        "https://github.com/albertzsigovits/malware-yara",
                        "https://github.com/baderj/yara",
                        "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip",
                        "https://gist.githubusercontent.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44/raw/iddqd.yar",
                        "https://gist.githubusercontent.com/pedramamini/c586a151a978f971b70412ca4485c491/raw/XProtect.yara",
                        "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip"
                    ]
                    # Self-heal source file
                    with open(SOURCES_FILE, "w", encoding="utf-8") as f:
                        f.write("# YARA Rule Sources (Generated Default)\n")
                        for s in sources: f.write(s + "\n")
                
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
                for i, url in enumerate(sources):
                    if self.abort_collection: break
                    self.after(0, lambda u=url: self.collector_status.set(f"Pulling: {urlparse(u).path.split('/')[-1]}"))
                    repo_name = urlparse(url).path.strip("/").replace("/", "_")
                    zip_path = TEMP_DIR / f"{repo_name}.zip"
                    
                    try:
                        is_raw = url.endswith((".yar", ".yara")) or "gist.githubusercontent.com" in url
                        if url.endswith(".zip"):
                            r = requests.get(url, headers=headers, timeout=60, stream=True)
                        elif is_raw:
                            r = requests.get(url, headers=headers, timeout=30, stream=True)
                        else:
                            r = requests.get(url + "/archive/refs/heads/master.zip", headers=headers, timeout=30, stream=True)
                            if r.status_code != 200:
                                r = requests.get(url + "/archive/refs/heads/main.zip", headers=headers, timeout=30, stream=True)
                        
                        if r.status_code == 200:
                            if is_raw and not url.endswith(".zip"):
                                # Handle single rule files
                                rule_name = url.split("/")[-1] if not url.endswith("/") else "rule.yar"
                                (STORAGE_DIR / repo_name).mkdir(parents=True, exist_ok=True)
                                with open(STORAGE_DIR / repo_name / rule_name, "wb") as f:
                                    for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
                                self.after(0, lambda n=repo_name: self.log_col(f"YARA rules downloaded: {n}", "success"))
                                continue # Skip zip extraction logic

                            with open(zip_path, 'wb') as f:
                                for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
                            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                                zip_ref.extractall(STORAGE_DIR / repo_name)
                            self.after(0, lambda n=repo_name: self.log_col(f"YARA rules downloaded: {n}", "success"))
                        else:
                            self.after(0, lambda u=url: self.log_col(f"Source unavailable: {u}", "warn"))
                    except Exception as ex:
                        self.after(0, lambda ex=ex: self.log_col(f"Pull error: {str(ex)[:60]}", "error"))
                    self.after(0, lambda p=(i+1)/len(sources)*0.4: self.col_progress.set(p))

                # Rebuild Master
                self.after(0, lambda: self.collector_status.set("Rebuilding Master File..."))
                files = sorted(list(STORAGE_DIR.rglob("*.yar*")))
                proc_rules = {}
                global_imports = set()
                
                for i, f in enumerate(files):
                    content = self.resolve_includes_gui(f)
                    if self.abort_collection: break
                    # Surgical extraction - STRICT regex
                    matches = list(re.finditer(r'(?m)^\s*(?:(?:global|private)\s+)?rule\s+([\w\.]+)(?:\s*:\s*[\w\s\.]+)?\s*\{', content))
                    rule_pos = [(m.start(), m.group(1)) for m in matches]
                    for j in range(len(rule_pos)):
                        start, rname = rule_pos[j]
                        # Use deep balancer on full content from rule start.
                        # Never pre-slice by next-rule position — regex/string braces fool that.
                        last = self.find_balanced_closing_brace(content, start_index=start)
                        if last == -1:
                            continue  # malformed / unbalanced rule, skip it
                        snippet = content[start:last+1]
                        # Removed: Silent Drop for Cuckoo/Incompatible modules
                        for imp in re.findall(r'import\s+"(.*?)"', snippet): global_imports.add(imp)
                        snippet = re.sub(r'import\s+".*?"\s*\n?', '', snippet)
                        
                        # PRE-VALIDATION: Advanced Compilation-Based Categorization
                        all_known_mods = ["pe", "elf", "macho", "hash", "math", "time", "dotnet", "dex", "lnk", "magic", "cuckoo", "console", "vt", "archive"]
                        env_specific_mods = ["dotnet", "dex", "lnk", "magic", "cuckoo", "console", "vt", "archive"]
                        
                        try:
                            # Attempt compilation with all possible modules that the LOCAL system supports
                            available_mods = set(yara.modules) if hasattr(yara, 'modules') else set(["pe", "elf", "hash", "math", "time"])
                            active_imps = '\n'.join([f'import "{m}"' for m in all_known_mods if m in available_mods])
                            yara.compile(source=f"{active_imps}\n{snippet}")
                        except Exception as ve:
                            err_msg = str(ve)
                            
                            # CATEGORIZATION LOGIC:
                            # We strictly split between Environmental/Dependency issues vs Genuine Syntax Errors.
                            is_env = 'undefined identifier' in err_msg.lower()
                            target_dir = ENV_SPECIFIC_DIR if is_env else QUARANTINE_DIR
                            suffix = "_env.yar" if is_env else "_err.yar"
                            
                            if is_env:
                                id_match = re.search(r'undefined identifier "(.*?)"', err_msg)
                                missing_id = id_match.group(1) if id_match else "unknown"
                                self.after(0, lambda r=rname, m=missing_id: self.log_col(f"Env-Specific: {r} requires '{m}' - Moving to support repo", "info"))
                            else:
                                self.after(0, lambda r=rname, msg=err_msg[:40]: self.log_col(f"Source Error: {r} is malformed ({msg}) - Saving", "warn"))

                            if not target_dir.exists(): target_dir.mkdir(parents=True, exist_ok=True)
                            (target_dir / f"{rname}{suffix}").write_text(snippet, encoding='utf-8')
                            
                            with open(SOURCE_LOG_FILE, "a", encoding="utf-8") as lf:
                                lf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Rule: {rname} | Error: {err_msg}\n")
                            
                            if not is_env:
                                with open(PROBLEMATIC_LIST_FILE, "a", encoding="utf-8") as pf: pf.write(f"{rname}_err\n")
                            
                            continue

                        if self.abort_collection: break
                        
                        # Handle Name Collisions (Append suffixes if ID already exists)
                        final_rname = rname
                        counter = 1
                        while final_rname in proc_rules:
                            final_rname = f"{rname}_{counter}"
                            counter += 1
                        
                        if final_rname != rname:
                            # Robust replacement: ignore leading whitespace and handle optional tags/braces
                            # We replace only the declaration part while keeping the rest of the snippet
                            snippet = re.sub(r'(\s*(?:(?:global|private)\s+)?rule\s+)' + re.escape(rname), 
                                           r'\g<1>' + final_rname, snippet, count=1)
                        
                        proc_rules[final_rname] = snippet
                    if i % 100 == 0: self.after(0, lambda i=i, t=len(files): self.col_progress.set(0.4 + (i/t)*0.2))

                # Force include all standard YARA modules to ensure high-grade rule compatibility
                standard_mods = ["pe", "elf", "macho", "dotnet", "cuckoo", "magic", "hash", "math", "time", "console", "dex", "archive"]
                available_mods = set(yara.modules) if hasattr(yara, 'modules') else set(standard_mods)
                for mod in standard_mods:
                    if mod in available_mods:
                        global_imports.add(mod)

                with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                    for imp in sorted(list(global_imports)): f.write(f'import "{imp}"\n')
                    f.write("\n")
                    for rcont in proc_rules.values(): f.write(rcont + "\n\n")
                
                self.after(0, lambda: self.log_col(f"Master rebuilt: {len(proc_rules)} rules total.", "success"))
                if self.abort_collection: return
                mode = "validate" # Cascade to validation

            if mode == "validate":
                if self.abort_collection: return
                self.after(0, lambda: self.collector_status.set("Validating Rules..."))
                self.after(0, lambda: self.log_col("Starting Validation Sweep...", "info"))
                self.validate_master_gui(OUTPUT_FILE, QUARANTINE_DIR, FIXED_DIR, ENV_SPECIFIC_DIR)

            if mode == "fix":
                if self.abort_collection: return
                self.after(0, lambda: self.collector_status.set("Repairing Problematic Rules..."))
                self.after(0, lambda: self.log_col("Initiating Auto-Fix Engine...", "info"))
                self.process_quarantine_fixes_gui(QUARANTINE_DIR, FIXED_DIR)

            if mode == "deduplicate":
                if self.abort_collection: return
                self.after(0, lambda: self.collector_status.set("Deduplicating Master Rules..."))
                self.after(0, lambda: self.log_col("Initiating Intelligent Deduplication Sweep...", "info"))
                self.deduplicate_directory_rules(MASTER_DIR)

            if mode == "ai_repair":
                if self.abort_collection: return
                self.after(0, lambda: self.collector_status.set("AI Batch Repairing..."))
                self.after(0, lambda: self.log_col("Initiating Automated AI Repair Sequence...", "info"))
                
                # Load AI Config
                cfg_path = base_dir / "config" / "AI.cfg"
                if not cfg_path.exists():
                    cfg_path.parent.mkdir(parents=True, exist_ok=True)
                    cfg_path.write_text('{"base_url": "https://api.openai.com/v1", "api_key": "", "model": "gpt-4o"}')
                
                try: ai_cfg = json.loads(cfg_path.read_text())
                except: ai_cfg = {"api_key": ""}
                
                api_key = ai_cfg.get("api_key")
                if not api_key:
                    self.after(0, lambda: messagebox.showerror("AI Error", "No API Key found in config/AI.cfg"))
                    return

                prob_files = list(QUARANTINE_DIR.glob("*.yar*"))
                total_prob = len(prob_files)
                for i, f_path in enumerate(prob_files):
                    if self.abort_collection: break
                    rname = f_path.stem
                    self.after(0, lambda n=rname, c=i+1, t=total_prob: self.collector_status.set(f"Repairing [{c}/{t}]: {n}"))
                    
                    content = f_path.read_text(encoding='utf-8', errors='ignore')
                    
                    # Pass 1 & 2
                    current_code = content
                    error_msg = "Unknown error"
                    try:
                        # Pre-check to get initial error
                        available_mods = set(yara.modules) if hasattr(yara, 'modules') else set()
                        test_mods = ["pe", "elf", "math", "hash", "dotnet", "macho", "dex", "magic", "time", "console"]
                        active_imps = '\n'.join([f'import "{m}"' for m in test_mods if m in available_mods]) + '\n'
                        yara.compile(source=active_imps + content)
                        # If somehow valid already
                        self.after(0, lambda n=rname: self.log_col(f"{n} is already valid - skipping", "info"))
                        continue
                    except Exception as e:
                        error_msg = str(e)

                    for attempt in range(1, 2):
                        # Re-validate to get fresh error if it was modified in attempt 1
                        try:
                            yara.compile(source=active_imps + current_code)
                            continue # Already fixed
                        except Exception as e_fresh:
                            error_msg = str(e_fresh)

                        self.after(0, lambda n=rname: self.log_col(f"AI fix attempt for {n}...", "info"))
                        prompt = f"Fix this YARA rule. It failed validation with this error:\n{error_msg}\n\n### RULE CONTENT ###\n{current_code}\n\n### FIX INSTRUCTIONS ###\nReturn ONLY the corrected YARA code. No markdown, no explanations."
                        payload = {
                            "model": ai_cfg.get("model", "gpt-4o"),
                            "messages": [{"role": "system", "content": "You are a YARA expert. Fix syntax errors. Return only code."}, {"role": "user", "content": prompt}],
                            "temperature": 0.2
                        }
                        try:
                            resp = requests.post(f"{ai_cfg.get('base_url','https://api.openai.com/v1')}/chat/completions", 
                                               headers={"Authorization": f"Bearer {api_key}"}, json=payload, timeout=40)
                            if resp.status_code == 200:
                                current_code = resp.json()['choices'][0]['message']['content'].strip()
                                current_code = re.sub(r'^```(yara)?\n?', '', current_code)
                                current_code = re.sub(r'\n?```$', '', current_code)
                                try:
                                    yara.compile(source=active_imps + current_code)
                                    with open(OUTPUT_FILE, "a", encoding="utf-8") as mf:
                                        mf.write(f"\n\n// --- AI Fixed Rule: {rname} ---\n")
                                        mf.write(current_code + "\n")
                                    f_path.unlink()
                                    self.after(0, lambda n=rname: self.log_col(f"✅ FIXED: {n} saved to master", "success"))
                                    is_fixed = True
                                    break
                                except Exception as e2:
                                    error_msg = str(e2)
                                    if attempt == 1:
                                        self.after(0, lambda n=rname: self.log_col(f"FAILED: {n} still has errors after AI attempt", "warn"))
                            else:
                                try: errmsg = resp.json().get('error', {}).get('message', 'Unknown Error')
                                except: errmsg = "Unknown Error"
                                self.after(0, lambda n=rname, s=resp.status_code, m=errmsg[:60]: 
                                             self.log_col(f"⚠️ AI Error ({s}): {m}", "error"))
                                break
                        except Exception as ex:
                            self.after(0, lambda n=rname, m=str(ex)[:30]: self.log_col(f"❌ Connection Error: {m}", "error"))
                            break
                    
                    if i % 10 == 0: self.after(0, lambda p=(i/total_prob): self.col_progress.set(p))

            self.after(0, lambda: self.col_progress.set(1.0))
            self.after(0, lambda: self.collector_status.set("Task complete"))
            self.after(0, lambda: self.log_col("Task complete", "success"))
            self.after(0, lambda: self.update_status("Task complete", "ok"))
            
            # Cleanup Logic
            if TEMP_DIR.exists(): shutil.rmtree(TEMP_DIR)
            
            # Remove empty folders if they are not needed
            for d in [FIXED_DIR, QUARANTINE_DIR]:
                if d.exists() and not any(d.iterdir()):
                    try: d.rmdir()
                    except: pass
            
        except Exception as e:
            self.after(0, lambda e=e: self.log_col(f"TASK STOPPED: {str(e)}", "error"))
            self.after(0, lambda: self.collector_status.set("Task failed"))
        finally:
            self.is_scanning = False
            self.after(0, lambda: self.btn_stop.configure(state="disabled"))
            self.after(0, lambda: [b.configure(state="normal") for b in self.collector_action_btns])

    def resolve_includes_gui(self, path, seen=None):
        if seen is None: seen = set()
        abs_p = Path(path).resolve()
        if abs_p in seen or not abs_p.exists(): return ""
        seen.add(abs_p)
        try:
            with open(abs_p, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
            def repl(m):
                inc = m.group(1).strip('"\'')
                return self.resolve_includes_gui(abs_p.parent / inc, seen)
            return re.sub(r'include\s+(".*?"|\'.*?\')', repl, content)
        except: return ""

    def validate_folders_gui(self, folder_path, valid_dest=None, invalid_dest=None):
        p = Path(folder_path)
        if not p.is_dir(): return
        available_mods = set(yara.modules)
        test_mods = ["pe","elf","math","hash","dotnet","macho","dex","magic","time","console","archive","cuckoo"]
        active_mods = [m for m in test_mods if m in available_mods]
        active_imps = '\n'.join([f'import "{m}"' for m in active_mods])

        valid_count = 0
        total_count = 0
        for f_path in p.glob("*.yar*"):
            if self.abort_collection: break
            total_count += 1
            try:
                content = f_path.read_text(encoding='utf-8', errors='ignore')
                yara.compile(source=f"{active_imps}\n{content}")
                valid_count += 1
                self.after(0, lambda n=f_path.name, d=p.name: self.log_col(f"[+] Recovery Check: {n} in '{d}' is now VALID", "success"))
                if valid_dest == "master":
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                        f.write(f"\n\n// --- Moving Rule: {f_path.name} ---\n")
                        f.write(content + "\n")
                    f_path.unlink()
                    self.after(0, lambda n=f_path.name: self.log_col(f"      -> MOVED to Master Rulebase", "success"))
                elif valid_dest:
                    dest = Path(valid_dest)
                    if dest.resolve() != p.resolve():
                        dest.mkdir(parents=True, exist_ok=True)
                        (dest / f_path.name).write_text(content, encoding='utf-8')
                        f_path.unlink()
                        self.after(0, lambda n=f_path.name, d=dest.name: self.log_col(f"      -> Moved to '{d}' repository", "success"))
            except Exception as e:
                # Less 'alarming' for problematic rule checks
                self.after(0, lambda n=f_path.name, msg=str(e)[:40]: self.log_col(f"[-] Recovery Check: {n} is still INVALID ({msg})", "info"))

        if total_count > 0:
            self.after(0, lambda v=valid_count, t=total_count, d=p.name: 
                         self.log_col(f"Sweep Summary for '{d}': {v} recovered / {t} checked", "info" if v==0 else "success"))

    def validate_master_gui(self, master_path, quarantine_dir, fixed_dir, env_specific_dir):
        # Stage 1: Deep Master Cleanup
        self.after(0, lambda: self.log_col("Validate and Cleanup Master Rule", "info"))
        last_error_rule = None
        rep_count = 0
        for _ in range(2000): # High ceiling for large files
            if self.abort_collection: break
            try:
                yara.compile(str(master_path))
                self.after(0, lambda: self.log_col("Master cleanup complete. All rules are valid.", "success"))
                break
            except yara.SyntaxError as e:
                match = re.search(r'\((\d+)\):', str(e))
                if not match: break
                line_no = int(match.group(1))
                text_lines = master_path.read_text(encoding='utf-8', errors='ignore').splitlines(True)
                
                # Relaxed rule header pattern — handle comments and varied spacing
                # Removed strict $ anchor to prevent matching previous valid rules
                rule_header_re = re.compile(r'^\s*(?:(?:global|private)\s+)?rule\s+[\w\.]+(?:\s*:\s*[\w\s\.]+)?\s*\{?', re.MULTILINE)
                start = next(
                    (i for i in range(min(line_no - 1, len(text_lines) - 1), -1, -1)
                     if rule_header_re.search(text_lines[i])),
                    -1
                )
                if start == -1: break
                full_text_from_start = "".join(text_lines[start:])
                rel_last_idx = self.find_balanced_closing_brace(full_text_from_start)
                
                if rel_last_idx != -1:
                    # Map relative index back to line index
                    acc_len = 0
                    end = start
                    for i in range(start, len(text_lines)):
                        acc_len += len(text_lines[i])
                        if acc_len > rel_last_idx:
                            end = i
                            break
                else:
                    end = len(text_lines) - 1
                
                bad_block = "".join(text_lines[start:end+1])
                rname_m = re.search(r'rule\s+([\w\.]+)', bad_block)
                rname = rname_m.group(1) if rname_m else f"err_{line_no}"
                
                if rname == last_error_rule:
                    rep_count += 1
                    if rep_count >= 2:
                        self.after(0, lambda r=rname: self.log_col(f"CRITICAL: Endless loop on rule '{r}'. MANUAL FIX REQUIRED.", "error"))
                        break
                else:
                    last_error_rule = rname
                    rep_count = 0

                if any(x in bad_block.lower() for x in ["cuckoo.", "cuckko.", 'import "cuckoo"', 'import "cuckko"']):
                    master_path.write_text("".join(text_lines[:start] + text_lines[end+1:]), encoding='utf-8')
                    self.after(0, lambda r=rname: self.log_col(f"Discarded incompatible rule: {r}", "info"))
                    continue

                err_msg = str(e).lower()
                is_env = "undefined identifier" in err_msg
                target_dir = env_specific_dir if is_env else quarantine_dir
                
                if not target_dir.exists(): target_dir.mkdir(parents=True, exist_ok=True)
                
                suffix = "_env.yar" if is_env else ".yar"
                (target_dir / f"{rname}{suffix}").write_text(bad_block, encoding='utf-8')
                master_path.write_text("".join(text_lines[:start] + text_lines[end+1:]), encoding='utf-8')
                
                # Update Status Logs based on category
                if is_env:
                    self.after(0, lambda r=rname: self.log_col(f"Env-Specific: {r} (Dependency Missing) -> Moving to support repo", "info"))
                else:
                    self.after(0, lambda r=rname: self.log_col(f"Problematic Rule: {r} (Syntax Error)", "warn"))
                    
                # Track problematic rules in external list (only for true errors)
                if not is_env:
                    base_dir = Path(__file__).parent.parent if not getattr(sys, 'frozen', False) else Path(sys.executable).parent
                    prob_file = base_dir / "problematic_rules.txt"
                    current_prob = set()
                    if prob_file.exists():
                        current_prob = set(line.strip() for line in prob_file.read_text().splitlines() if line.strip())
                    if rname not in current_prob:
                        with open(prob_file, "a", encoding="utf-8") as pf: pf.write(f"{rname}\n")
        
        # Final verification that Master is now clean
        try:
            yara.compile(str(master_path))
            self.after(0, lambda: self.log_col("SUCCESS: Master Rulebase is now 100% Valid.", "success"))
        except Exception as e:
            self.after(0, lambda: self.log_col(f"Cleanup finished, but Master still has remaining issues. Run again or check logs.", "info"))

    def process_quarantine_fixes_gui(self, q_dir, f_dir):
        available_mods = set(yara.modules)
        active_imps = '\n'.join([f'import "{m}"' for m in ["pe","math","hash","dotnet","magic","time","elf","macho","dex","console"] if m in available_mods])
        files = list(q_dir.glob("*.yar*"))
        success_count = 0 
        # Load problematic list for removal tracking
        base_dir = Path(__file__).parent.parent if not getattr(sys, 'frozen', False) else Path(sys.executable).parent
        prob_file = base_dir / "problematic_rules.txt"

 
        for i, f_path in enumerate(files):
            if self.abort_collection: break
            # Prevent "Stuck" on massive rules
            if f_path.stat().st_size > 10 * 1024 * 1024: 
                self.after(0, lambda n=f_path.name: self.log_col(f"Skipping {n}: Too large (>10MB)", "warn"))
                continue
            
            # 1. Logging Start
            rname = f_path.stem
            self.after(0, lambda n=rname: self.log_col(f"Checking {n} for existing validity...", "info"))
            
            try:
                c_orig = f_path.read_text(encoding='utf-8', errors='ignore')
                
                # Pre-validation: If it's already valid, promote immediately
                try:
                    yara.compile(source=f"{active_imps}\n{c_orig}")
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as mf:
                        mf.write(f"\n\n// --- Validated & Moved: {f_path.name} ---\n")
                        mf.write(c_orig + "\n")
                    f_path.unlink()
                    success_count += 1
                    self.after(0, lambda n=rname: self.log_col(f"✅ Already valid: {n} promoted to master.", "success"))
                    continue
                except:
                    self.after(0, lambda n=rname: self.log_col(f"❌ {n} is invalid. Attempting Basic Fix...", "info"))

                c = c_orig

                # 0. Fix Invalid Rule Names (Identifiers cannot start with digits in YARA)
                def fix_lab_rule_name(m):
                    prefix, name = m.group(1), m.group(2)
                    # Strip leading hex/versioning junk: 0x12_, 01_, etc. if followed by alpha
                    clean_name = re.sub(r'^[0-9a-fA-Fx_]+(?=[a-zA-Z])', '', name)
                    # If still invalid (starts with digit) or becomes empty, prefix it
                    if not clean_name or clean_name[0].isdigit():
                        clean_name = "rule_" + clean_name
                    return f"{prefix}{clean_name}"
                c = re.sub(r'(?m)^(\s*(?:(?:global|private)\s+)?rule\s+)([\w\.]+)', fix_lab_rule_name, c)

                # 1. Generic & Module Fixes
                c = c.replace('\x00', '\\x00').replace('\\0', '\\x00')
                c = c.replace('+?', '+').replace('*?', '*').replace('??', '?')
                for mod in ["magic", "lnk", "pe", "dotnet", "elf", "macho"]:
                    if f'{mod}.' in c and f'import "{mod}"' not in c: c = f'import "{mod}"\n' + c
                
                # Mask failing fields
                failing = [
                    "magic.mime_type", "magic.is_lnk", "lnk.is_lnk", "lnk.creation_time", "lnk.access_time", "lnk.modification_time",
                    "lnk.birth_time", "lnk.header_size", "pe.network", "is_uint16", "cuckoo.", "network.", "net.", "creation_time",
                    "access_time", "modification_time"
                ]
                for field in failing:
                    if field in c: c = re.sub(f'^.*{re.escape(field)}.*$', r'// \g<0>', c, flags=re.MULTILINE)

                # Resolve Duplicated IDs
                lines = c.splitlines()
                seen_ids = set()
                for idx in range(len(lines)):
                    m = re.search(r'^\s*(\$[\w]+)\s*=', lines[idx])
                    if m:
                        sid = m.group(1)
                        if sid in seen_ids: lines[idx] = lines[idx].replace(sid, f"{sid}_dup_{idx}", 1)
                        seen_ids.add(sid)
                c = "\n".join(lines)

                # Condition Restoration
                if 'condition:' not in c.lower():
                    if 'strings:' in c.lower(): c += "\ncondition:\n    any of them"
                    else: c += "\ncondition:\n    true"

                # Surgical String Correction
                if 'condition:' in c:
                    parts = c.split('condition:', 1)
                    defined = set(re.findall(r'(\$[\w]+)\s*=', parts[0]))
                    used = set(re.findall(r'(\$[\w]+)', parts[1]))
                    for u in (used - defined):
                        if 'strings:' in parts[0]: parts[0] = parts[0].replace('strings:', f'strings:\n        {u} = "dummy_fix"', 1)
                        else: parts[0] = parts[0].strip() + f'\n    strings:\n        {u} = "dummy_fix"\n'
                    defined = set(re.findall(r'(\$[\w]+)\s*=', parts[0]))
                    unref = (defined - used)
                    if unref: c = parts[0] + "condition:\n       (0==1 and " + " or ".join(unref) + ") or " + parts[1]
                    else: c = "condition:".join(parts)
                
                # Regex & Brace Sanitization
                c = c.replace('/$re/', '/re/').replace('/$re', '/re')
                open_b = c.count('{')
                close_b = c.count('}')
                while open_b > close_b:
                    c += "\n}"
                    close_b += 1
                while close_b > open_b and c.strip().endswith("}"):
                    c = c.strip()[:-1].strip()
                    close_b -= 1
                
                # Validation test
                yara.compile(source=f"{active_imps}\n{c}")
                
                # SUCCESS: Write to master
                success_count += 1
                with open(OUTPUT_FILE, "a", encoding="utf-8") as mf:
                    mf.write(f"\n\n// --- Moved Fixed Rule: {f_path.name} ---\n")
                    mf.write(c + "\n")
                
                # Clean up manifest
                if prob_file.exists():
                    current_prob = set(line.strip() for line in prob_file.read_text().splitlines() if line.strip())
                    if rname in current_prob:
                        current_prob.remove(rname)
                        prob_file.write_text("\n".join(sorted(list(current_prob))) + "\n", encoding='utf-8')
                
                f_path.unlink()
                self.after(0, lambda n=rname: self.log_col(f"FIX SUCCESS: {n} repaired and added to master.", "success"))
                
            except Exception as e:
                self.after(0, lambda n=rname: self.log_col(f"FIX FAILED: {n} still invalid after repair pass.", "warn"))
            
            self.after(0, lambda i=i, t=len(files): self.col_progress.set((i+1)/t))

        # 3. Final Verification Sweep: Promote anything valid remaining in folders
        for folder in [q_dir, f_dir]:
            for rem_path in folder.glob("*.yar*"):
                try:
                    c_rem = rem_path.read_text(encoding='utf-8', errors='ignore')
                    yara.compile(source=f"{active_imps}\n{c_rem}")
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as mf:
                        mf.write(f"\n\n// --- Sweep Fixed Rule: {rem_path.name} ---\n")
                        mf.write(c_rem + "\n")
                    rem_path.unlink()
                    success_count += 1
                    self.after(0, lambda n=rem_path.name: self.log_col(f"Sweep Promo: {n} is valid.", "success"))
                except:
                    pass

        self.after(0, lambda s=success_count: self.log_col(f"Task complete. {s} rules moved to master.", "success"))

    def deduplicate_directory_rules(self, folder_path):
        self.after(0, lambda: self.log_col(f"Analyzing {folder_path.name} for identifier collisions...", "info"))
        seen_rules = {} # rule_name -> first_file_found
        files = sorted(list(folder_path.rglob("*.yar*")))
        total_removed = 0

        for f_path in files:
            if self.abort_collection: break
            try:
                content = f_path.read_text(encoding='utf-8', errors='ignore')
                # STRICT REGEX: Must be at start of line, followed by name, optional tags, and an opening brace
                # This prevents matching "rule" inside natural language comments.
                matches = list(re.finditer(r'(?m)^\s*(?:(?:global|private)\s+)?rule\s+([\w\.]+)(?:\s*:\s*[\w\s\.]+)?\s*\{', content))
                
                if not matches: continue
                
                rule_pos = [(m.start(), m.group(1)) for m in matches]
                pre_content = content[:rule_pos[0][0]]
                kept_blocks = [pre_content]
                removed_in_file = 0
                
                for i in range(len(rule_pos)):
                    start, rname = rule_pos[i]
                    end_search = rule_pos[i+1][0] if i+1 < len(rule_pos) else len(content)
                    block_full = content[start:end_search]
                    
                    # Deep brace balancing to extract the rule block precisely
                    last_idx = self.find_balanced_closing_brace(block_full)
                    
                    if last_idx != -1:
                        rule_block = block_full[:last_idx+1]
                        trailing_after_rule = block_full[last_idx+1:]
                        
                        if rname in seen_rules:
                            removed_in_file += 1
                            total_removed += 1
                            # Discard the rule_block but keep the trailing spacing/comments
                            kept_blocks.append(trailing_after_rule)
                        else:
                            seen_rules[rname] = f_path.name
                            kept_blocks.append(block_full) # Keep as is
                    else:
                        # Fallback for malformed rules
                        kept_blocks.append(block_full)

                if removed_in_file > 0:
                    new_content = "".join(kept_blocks)
                    # Simple cleanup of excessive newlines (max 3 in a row)
                    new_content = re.sub(r'\n{4,}', '\n\n\n', new_content)
                    f_path.write_text(new_content, encoding='utf-8')
                    self.after(0, lambda f=f_path.name, n=removed_in_file: 
                                self.log_col(f"Cleaned up {f}: Removed {n} duplicate rules.", "success"))
            except Exception as e:
                self.after(0, lambda f=f_path.name, err=str(e): self.log_col(f"Error checking {f}: {err}", "error"))

        self.after(0, lambda n=total_removed: 
                    self.log_col(f"Deduplication Complete. Total identifiers resolved: {n}", "success"))

    def handle_editor_drop(self, event):
        # Forensic-grade path parsing (Handles spaces, braces, and Tcl lists)
        try:
            files = self.tk.splitlist(event.data)
            if not files: return
            
            path = files[0]
            # Extra cleanse for Windows braces
            if path.startswith('{') and path.endswith('}'): path = path[1:-1]
            
            p_obj = Path(path)
            if p_obj.is_file():
                # Preliminary size check before loading into memory
                if p_obj.stat().st_size > 5 * 1024 * 1024:
                    messagebox.showwarning("Safety", "Critical Error: Rule file exceeds 5MB memory limit.")
                    return

                content = p_obj.read_text(encoding='utf-8', errors='ignore')
                
                # Full validation check
                if self.check_editor_limits(content): return

                self.lab_editor.delete("1.0", "end")
                self.lab_editor.insert("1.0", content)
                self.lab_rule_path.set(path)
                self.on_editor_change()
                self.update_lab_buttons_state()
                self.update_status(f"Ingested: {p_obj.name}", "ok")
                self.lab_status.configure(text=f"LOADED: {p_obj.name}", text_color=CLR_SUCCESS)
            else:
                self.update_status("Error: Drop a single YARA file", "error")
        except Exception as e:
            self.update_status(f"DND Engine Error: {str(e)[:30]}", "error")

    def find_balanced_closing_brace(self, text, start_index=0):
        """Advanced brace balancer that respects all YARA literal types.
        Handles: "double-quoted", 'single-quoted', /regex/ strings,
        escaped quotes/backslashes, // and /* */ comments.
        Braces inside any literal or comment are NOT counted.
        """
        bc = 0
        found_first = False
        in_dquote = False        # inside "..." string
        in_squote = False        # inside '...' string
        in_regex = False         # inside /.../ regex string
        in_comment_single = False
        in_comment_multi = False

        def _count_preceding_backslashes(pos):
            num = 0
            j = pos - 1
            while j >= 0 and text[j] == '\\':
                num += 1
                j -= 1
            return num

        i = start_index
        while i < len(text):
            char = text[i]

            # ── Inside a double-quoted string ─────────────────────────────────
            if in_dquote:
                if char == '"' and _count_preceding_backslashes(i) % 2 == 0:
                    in_dquote = False

            # ── Inside a single-quoted string ────────────────────────────────
            elif in_squote:
                if char == "'" and _count_preceding_backslashes(i) % 2 == 0:
                    in_squote = False

            # ── Inside a /regex/ literal ──────────────────────────────────────
            elif in_regex:
                # A closing / that is not escaped ends the regex
                if char == '/' and _count_preceding_backslashes(i) % 2 == 0:
                    in_regex = False

            # ── Inside a // comment ───────────────────────────────────────────
            elif in_comment_single:
                if char == '\n':
                    in_comment_single = False

            # ── Inside a /* */ comment ────────────────────────────────────────
            elif in_comment_multi:
                if char == '*' and i + 1 < len(text) and text[i+1] == '/':
                    in_comment_multi = False
                    i += 1

            # ── Normal parsing context ────────────────────────────────────────
            else:
                if char == '"':
                    in_dquote = True
                elif char == "'":
                    in_squote = True
                elif char == '/':
                    next_ch = text[i+1] if i + 1 < len(text) else ''
                    if next_ch == '/':
                        in_comment_single = True
                        i += 1
                    elif next_ch == '*':
                        in_comment_multi = True
                        i += 1
                    else:
                        # Detect YARA regex: look back for '=' (possibly with spaces)
                        k = i - 1
                        while k >= 0 and text[k] in ' \t':
                            k -= 1
                        if k >= 0 and text[k] == '=':
                            in_regex = True
                elif char == '{':
                    bc += 1
                    found_first = True
                elif char == '}':
                    bc -= 1
                    if found_first and bc == 0:
                        return i
            i += 1
        return -1

if __name__ == "__main__":
    app = YaraPlaygroundApp()
    app.mainloop()
